//! Open connections: connecting and authenticating, the registry that hands each connection to
//! whoever presents its token, idle expiry, and the status report.

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    ops::Deref,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use russh::{
    MethodKind, MethodSet, Preferred, cipher,
    client::{self, KeyboardInteractiveAuthResponse},
    kex,
    keys::{
        PrivateKeyWithHashAlg,
        agent::AgentIdentity,
        decode_secret_key,
        signature::Signer as _,
        ssh_encoding::Encode,
        ssh_key::{Algorithm, Certificate, HashAlg, PrivateKey, private::KeypairData},
    },
    mac,
};
use tokio_util::sync::CancellationToken;

use crate::{
    client::{
        CLOSE_TIMEOUT, ClientHandler, HandshakeFacts, RemoteForwardTargets, SshHandle, best_effort,
    },
    forward::ForwardTable,
    host_key::{HostKeyPolicy, HostKeyReport, Verdict, Verification},
    output::{ToolError, format_duration, lock, random_hex},
    paths::{read_small_file, resolve_local_path},
    sftp::SftpState,
    shell::ShellTable,
};

/// The largest private key or certificate file read.
const MAX_KEY_FILE_BYTES: u64 = 1024 * 1024;

/// How often the server checks for connections that have been idle past their timeout.
const REAP_INTERVAL: Duration = Duration::from_secs(15);

/// How long a connection may go without hearing from the server before a keepalive is sent.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// How many keepalives in a row may go unanswered before the connection is closed.
const KEEPALIVE_MAX: usize = 4;

/// The rounds of keyboard-interactive questions answered with the password before giving up.
const KEYBOARD_INTERACTIVE_ROUNDS: usize = 3;

/// The most characters of a keyboard-interactive question a result quotes.
const QUESTION_CHARS: usize = 100;

/// Who and where a connection logs in.
#[derive(Clone, Debug)]
pub(crate) struct Target {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) user: String,
}

impl Target {
    fn describe(&self) -> String {
        if self.port == 22 {
            format!("{}@{}", self.user, self.host)
        } else {
            format!("{}@{}:{}", self.user, self.host, self.port)
        }
    }
}

/// One open connection.
pub(crate) struct Connection {
    pub(crate) token: String,
    pub(crate) target: Target,
    pub(crate) handle: Arc<SshHandle>,
    pub(crate) host_key: HostKeyReport,
    pub(crate) verification: Verification,
    pub(crate) authentication: String,
    pub(crate) server_version: String,
    pub(crate) banner: Option<String>,
    pub(crate) via: Option<Arc<Connection>>,
    pub(crate) idle_timeout: Option<Duration>,
    pub(crate) opened_at: Instant,
    last_used: Mutex<Instant>,
    /// Tool calls using this connection right now; a connection in use is never idle.
    calls_in_flight: AtomicUsize,
    pub(crate) shells: Mutex<ShellTable>,
    pub(crate) forwards: Mutex<ForwardTable>,
    pub(crate) remote_forward_targets: RemoteForwardTargets,
    pub(crate) sftp: SftpState,
    /// Canceled when this connection is closed, which stops its forwards' listeners.
    pub(crate) closed: CancellationToken,
}

impl Connection {
    /// Record a use of this connection and of every connection it is tunneled through, so a jump
    /// host does not expire while the connection through it is in use.
    fn touch(&self) {
        *lock(&self.last_used) = Instant::now();
        if let Some(via) = &self.via {
            via.touch();
        }
    }

    fn idle_for(&self) -> Duration {
        lock(&self.last_used).elapsed()
    }

    /// Whether the idle timeout has passed with no tool call using the connection.
    fn is_idle_past_timeout(&self) -> bool {
        self.calls_in_flight.load(Ordering::SeqCst) == 0
            && self
                .idle_timeout
                .is_some_and(|timeout| self.idle_for() >= timeout)
    }

    /// Whether the server identifies as OpenSSH, whose SFTP server reads symlink requests with
    /// their two paths reversed.
    pub(crate) fn is_openssh(&self) -> bool {
        self.server_version.contains("OpenSSH")
    }

    /// End the connection and everything on it.
    async fn close(&self) {
        self.closed.cancel();
        best_effort(
            CLOSE_TIMEOUT,
            &format!("disconnecting {}", self.target.describe()),
            self.handle
                .disconnect(russh::Disconnect::ByApplication, "", "en"),
        )
        .await;
    }

    /// The report `connection_status` returns.
    pub(crate) fn describe(&self) -> String {
        let mut lines = vec![format!("Connection to {}", self.target.describe())];
        if let Some(via) = &self.via {
            lines.push(format!("Through: {}", via.chain()));
        }
        lines.push(format!("Server: {}", self.server_version));
        lines.push(format!("Logged in with: {}", self.authentication));
        lines.push(format!(
            "{} ({})",
            self.host_key.describe(),
            self.verification.describe()
        ));
        let idle = match self.idle_timeout {
            Some(timeout) => format!(
                "; closes after {} idle ({} left)",
                format_duration(timeout),
                format_duration(timeout.saturating_sub(self.idle_for()))
            ),
            None => "; no idle timeout".to_owned(),
        };
        lines.push(format!(
            "Open for {}{idle}",
            format_duration(self.opened_at.elapsed())
        ));
        let shells = lock(&self.shells).describe();
        if shells.is_empty() {
            lines.push("Shells: none".to_owned());
        } else {
            lines.push("Shells:".to_owned());
            lines.extend(shells.into_iter().map(|line| format!("  {line}")));
        }
        let forwards = lock(&self.forwards).describe();
        if !forwards.is_empty() {
            lines.push("Forwards:".to_owned());
            lines.extend(forwards.into_iter().map(|line| format!("  {line}")));
        }
        lines.join("\n")
    }

    fn chain(&self) -> String {
        match &self.via {
            Some(via) => format!("{}, then {}", via.chain(), self.target.describe()),
            None => self.target.describe(),
        }
    }
}

/// Every open connection, reachable only through its token.
#[derive(Default)]
pub(crate) struct Registry {
    connections: Mutex<HashMap<String, Arc<Connection>>>,
}

/// The refusal for a token that names no connection in the registry. It reads the same whether
/// the token never existed or belonged to a connection that was disconnected or closed as idle,
/// so it reveals nothing. (A connection the server ended is still in the registry when its token
/// is next presented, and that caller is told where it led.)
fn unknown_token() -> ToolError {
    ToolError::new(
        "No open connection has that token. It may have been disconnected, closed after being idle, or opened by a server process that has since restarted; connect again.",
    )
}

/// One tool call's use of a connection. While it lives the connection is in use, so it is never
/// closed as idle, and dropping it records the end of the use.
pub(crate) struct ConnectionUse {
    connection: Arc<Connection>,
}

impl ConnectionUse {
    /// The connection itself, for something that outlives this call, such as a connection
    /// tunneled through it.
    pub(crate) fn shared(&self) -> Arc<Connection> {
        Arc::clone(&self.connection)
    }
}

impl Deref for ConnectionUse {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        &self.connection
    }
}

impl Drop for ConnectionUse {
    fn drop(&mut self) {
        self.connection.touch();
        self.connection
            .calls_in_flight
            .fetch_sub(1, Ordering::SeqCst);
    }
}

impl Registry {
    /// Look up the connection `token` names for the duration of one tool call.
    pub(crate) fn get(&self, token: &str) -> Result<ConnectionUse, ToolError> {
        let mut connections = lock(&self.connections);
        let connection = connections.get(token).cloned().ok_or_else(unknown_token)?;
        if connection.handle.is_closed() {
            connections.remove(token);
            drop(connections);
            connection.closed.cancel();
            return Err(ToolError::new(format!(
                "The connection to {} has ended: the server closed it or stopped answering. Connect again.",
                connection.target.describe()
            )));
        }
        // Counted while the registry is locked, so the idle reaper, which decides under the same
        // lock, cannot close the connection between this lookup and its use.
        connection.calls_in_flight.fetch_add(1, Ordering::SeqCst);
        drop(connections);
        connection.touch();
        Ok(ConnectionUse { connection })
    }

    fn insert(&self, connection: Arc<Connection>) {
        lock(&self.connections).insert(connection.token.clone(), connection);
    }

    /// Close the connection `token` names, and every connection tunneled through it, which would
    /// end with it anyway.
    pub(crate) async fn disconnect(&self, token: &str) -> Result<String, ToolError> {
        let (connection, dependents) = {
            let mut connections = lock(&self.connections);
            let connection = connections.remove(token).ok_or_else(unknown_token)?;
            let mut removed = vec![token.to_owned()];
            let mut dependents = Vec::new();
            loop {
                let carried: Vec<String> = connections
                    .values()
                    .filter(|other| {
                        other
                            .via
                            .as_ref()
                            .is_some_and(|via| removed.contains(&via.token))
                    })
                    .map(|other| other.token.clone())
                    .collect();
                if carried.is_empty() {
                    break;
                }
                for token in carried {
                    if let Some(dependent) = connections.remove(&token) {
                        dependents.push(dependent);
                        removed.push(token);
                    }
                }
            }
            (connection, dependents)
        };
        // The innermost first, while the tunnels they run through are still open.
        for dependent in dependents.iter().rev() {
            dependent.close().await;
        }
        connection.close().await;
        let mut text = format!("Disconnected from {}.", connection.target.describe());
        match dependents.len() {
            0 => {}
            1 => text.push_str(" 1 connection tunneled through it was closed too."),
            count => text.push_str(&format!(
                " {count} connections tunneled through it were closed too."
            )),
        }
        Ok(text)
    }

    /// Close every connection idle past its timeout.
    async fn reap_idle(&self) {
        let expired: Vec<Arc<Connection>> = {
            let mut connections = lock(&self.connections);
            // A jump host stays open while a connection through it does, whatever its own idle
            // time, since closing it would end that connection too.
            let carrying: HashSet<String> = connections
                .values()
                .filter_map(|connection| connection.via.as_ref().map(|via| via.token.clone()))
                .collect();
            let tokens: Vec<String> = connections
                .values()
                .filter(|connection| {
                    connection.handle.is_closed()
                        || (connection.is_idle_past_timeout()
                            && !carrying.contains(&connection.token))
                })
                .map(|connection| connection.token.clone())
                .collect();
            tokens
                .iter()
                .filter_map(|token| connections.remove(token))
                .collect()
        };
        for connection in expired {
            tracing::info!(
                "closing the connection to {}: idle or ended",
                connection.target.describe()
            );
            connection.close().await;
        }
    }

    /// Start the task that closes idle connections for the life of the process.
    pub(crate) fn spawn_reaper(self: &Arc<Self>) {
        let registry = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(REAP_INTERVAL);
            loop {
                interval.tick().await;
                let Some(registry) = registry.upgrade() else {
                    break;
                };
                registry.reap_idle().await;
            }
        });
    }
}

/// Where a private key or certificate comes from.
pub(crate) enum Material {
    Content(String),
    File(String),
}

impl Material {
    fn read(&self, argument: &str) -> Result<String, ToolError> {
        match self {
            Self::Content(content) => Ok(content.clone()),
            Self::File(path) => {
                let path = resolve_local_path(argument, path)?;
                read_small_file(argument, &path, MAX_KEY_FILE_BYTES)
            }
        }
    }
}

/// Everything `connect` needs.
pub(crate) struct ConnectRequest {
    pub(crate) target: Target,
    pub(crate) private_key: Option<Material>,
    pub(crate) private_key_passphrase: Option<String>,
    pub(crate) certificate: Option<Material>,
    pub(crate) password: Option<String>,
    pub(crate) host_key_fingerprints: Vec<String>,
    pub(crate) known_hosts_file: Option<String>,
    pub(crate) accept_new_host_key: bool,
    pub(crate) via: Option<Arc<Connection>>,
    pub(crate) allow_legacy_algorithms: bool,
    pub(crate) idle_timeout: Option<Duration>,
    pub(crate) connect_timeout: Duration,
}

fn load_private_key(
    material: &Material,
    passphrase: Option<&str>,
) -> Result<PrivateKey, ToolError> {
    let argument = match material {
        Material::Content(_) => "private_key",
        Material::File(_) => "private_key_file",
    };
    let text = material.read(argument)?;
    let encrypted = || {
        ToolError::new(format!(
            "The key in {argument} is encrypted; pass private_key_passphrase."
        ))
    };
    decode_secret_key(&text, passphrase).map_err(|error| match error {
        russh::keys::Error::KeyIsEncrypted => encrypted(),
        _ if passphrase.is_none() && is_encrypted_key(&text) => encrypted(),
        _ if passphrase.is_some() => ToolError::new(format!(
            "The key in {argument} could not be read: the passphrase may be wrong, or it is not a private key."
        )),
        _ => ToolError::new(format!(
            "{argument} does not hold a private key in a format this server reads (OpenSSH, PEM or PuTTY)."
        )),
    })
}

/// Whether key text is an encrypted PuTTY or PKCS#8 key. Their decoders fail on one without a
/// passphrase as on an unreadable key, while OpenSSH and PKCS#5 keys report the encryption.
fn is_encrypted_key(text: &str) -> bool {
    text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
        || text.lines().any(|line| {
            line.strip_prefix("Encryption:")
                .is_some_and(|value| value.trim() != "none")
        })
}

fn load_certificate(material: &Material) -> Result<Certificate, ToolError> {
    let argument = match material {
        Material::Content(_) => "certificate",
        Material::File(_) => "certificate_file",
    };
    let text = material.read(argument)?;
    Certificate::from_openssh(text.trim())
        .map_err(|_| ToolError::new(format!("{argument} does not hold an OpenSSH certificate.")))
}

/// Algorithms appended after the defaults when `allow_legacy_algorithms` is set: SHA-1 key
/// exchange and MACs, CBC and 3DES ciphers and DSA keys for servers too old to speak anything
/// newer, and the NIST curve key exchanges and AES-128-GCM, which russh's defaults leave out but
/// some servers (such as ones restricted to FIPS algorithms) require.
fn legacy_preferences(mut preferred: Preferred) -> Preferred {
    let mut kex_names = preferred.kex.to_vec();
    kex_names.extend([
        kex::ECDH_SHA2_NISTP256,
        kex::ECDH_SHA2_NISTP384,
        kex::ECDH_SHA2_NISTP521,
        kex::DH_GEX_SHA1,
        kex::DH_G14_SHA1,
        kex::DH_G1_SHA1,
    ]);
    let mut ciphers = preferred.cipher.to_vec();
    ciphers.extend([
        cipher::AES_128_GCM,
        cipher::AES_256_CBC,
        cipher::AES_192_CBC,
        cipher::AES_128_CBC,
        cipher::TRIPLE_DES_CBC,
    ]);
    let mut macs = preferred.mac.to_vec();
    macs.extend([mac::HMAC_SHA1_ETM, mac::HMAC_SHA1]);
    let mut keys = preferred.key.to_vec();
    keys.push(Algorithm::Dsa);
    preferred.kex = Cow::Owned(kex_names);
    preferred.cipher = Cow::Owned(ciphers);
    preferred.mac = Cow::Owned(macs);
    preferred.key = Cow::Owned(keys);
    preferred
}

/// Move the host key algorithms the policy can check to the front, keeping the rest in order.
fn prefer_checkable_keys(mut preferred: Preferred, first: &[Algorithm]) -> Preferred {
    if first.is_empty() {
        return preferred;
    }
    let same_family = |a: &Algorithm, b: &Algorithm| match (a, b) {
        (Algorithm::Rsa { .. }, Algorithm::Rsa { .. }) => true,
        _ => a == b,
    };
    let (mut front, back): (Vec<Algorithm>, Vec<Algorithm>) = preferred
        .key
        .iter()
        .cloned()
        .partition(|algorithm| first.iter().any(|wanted| same_family(algorithm, wanted)));
    front.extend(back);
    preferred.key = Cow::Owned(front);
    preferred
}

fn new_token() -> Result<String, ToolError> {
    Ok(format!("conn_{}", random_hex(16)?))
}

/// Open, verify and authenticate a connection and add it to `registry`, returning the result text.
/// Nothing is registered until the last await has passed, so a caller that drops this future on
/// cancellation leaves no connection behind.
pub(crate) async fn connect(
    registry: &Registry,
    request: ConnectRequest,
) -> Result<String, ToolError> {
    let target = request.target.clone();
    if target.host.trim().is_empty() {
        return Err(ToolError::new("host is empty."));
    }
    if target.user.trim().is_empty() {
        return Err(ToolError::new("user is empty."));
    }
    if request.certificate.is_some() && request.private_key.is_none() {
        return Err(ToolError::new(
            "A certificate needs its private key: pass private_key or private_key_file too.",
        ));
    }
    let key = request
        .private_key
        .as_ref()
        .map(|material| load_private_key(material, request.private_key_passphrase.as_deref()))
        .transpose()?
        .map(Arc::new);
    let certificate = request
        .certificate
        .as_ref()
        .map(load_certificate)
        .transpose()?;
    let known_hosts_file = request
        .known_hosts_file
        .as_deref()
        .map(|path| resolve_local_path("known_hosts_file", path))
        .transpose()?;
    let policy = Arc::new(HostKeyPolicy::from_arguments(
        request.host_key_fingerprints.clone(),
        known_hosts_file,
        request.accept_new_host_key,
    )?);

    let legacy = request.allow_legacy_algorithms;
    let mut preferred = Preferred::default();
    if legacy {
        preferred = legacy_preferences(preferred);
    }
    preferred = prefer_checkable_keys(
        preferred,
        &policy.preferred_algorithms(&target.host, target.port),
    );
    let config = Arc::new(client::Config {
        preferred,
        keepalive_interval: Some(KEEPALIVE_INTERVAL),
        keepalive_max: KEEPALIVE_MAX,
        nodelay: true,
        ..client::Config::default()
    });
    let facts = Arc::new(Mutex::new(HandshakeFacts::default()));
    let remote_forward_targets = RemoteForwardTargets::default();
    let handler = ClientHandler::new(
        target.host.clone(),
        target.port,
        Arc::clone(&policy),
        Arc::clone(&facts),
        Arc::clone(&remote_forward_targets),
    );

    let handshake = async {
        match &request.via {
            Some(via) => {
                let channel = via
                    .handle
                    .channel_open_direct_tcpip(
                        target.host.as_str(),
                        u32::from(target.port),
                        "127.0.0.1",
                        0,
                    )
                    .await
                    .map_err(|error| {
                        ToolError::new(format!(
                            "{} could not reach {}:{}: {error}",
                            via.target.describe(),
                            target.host,
                            target.port
                        ))
                    })?;
                client::connect_stream(config, channel.into_stream(), handler)
                    .await
                    .map_err(|error| handshake_failure(&facts, &target, &error, legacy))
            }
            None => client::connect(config, (target.host.as_str(), target.port), handler)
                .await
                .map_err(|error| handshake_failure(&facts, &target, &error, legacy)),
        }
    };
    let mut handle = tokio::time::timeout(request.connect_timeout, handshake)
        .await
        .map_err(|_| {
            ToolError::new(format!(
                "Connecting to {}:{} timed out after {}.",
                target.host,
                target.port,
                format_duration(request.connect_timeout)
            ))
        })??;

    let (host_key, verification, server_version) = {
        let facts = lock(&facts);
        let Some((report, Verdict::Accepted(verification))) = facts.host_key.clone() else {
            return Err(ToolError::new("The server's host key was not checked."));
        };
        (
            report,
            verification,
            facts.server_version.clone().unwrap_or_default(),
        )
    };

    let authentication = tokio::time::timeout(
        request.connect_timeout,
        authenticate(&mut handle, &target, Credentials {
            key,
            certificate,
            password: request.password.as_deref(),
            allow_sha1_rsa: legacy,
        }),
    )
    .await
    .map_err(|_| {
        ToolError::new(format!(
            "Logging in to {} timed out after {}.",
            target.describe(),
            format_duration(request.connect_timeout)
        ))
    })??;
    // The server sends its banner during authentication, so it is read only now.
    let banner = lock(&facts).banner.clone();

    let connection = Arc::new(Connection {
        token: new_token()?,
        target,
        handle: Arc::new(handle),
        host_key,
        verification,
        authentication,
        server_version,
        banner,
        via: request.via,
        idle_timeout: request.idle_timeout,
        opened_at: Instant::now(),
        last_used: Mutex::new(Instant::now()),
        calls_in_flight: AtomicUsize::new(0),
        shells: Mutex::new(ShellTable::default()),
        forwards: Mutex::new(ForwardTable::default()),
        remote_forward_targets,
        sftp: SftpState::default(),
        closed: CancellationToken::new(),
    });
    registry.insert(Arc::clone(&connection));

    let mut text = format!(
        "Connected to {} as {}.\nconnection: {}\nServer: {}\nLogged in with: {}\n{} ({})",
        connection.target.host,
        connection.target.user,
        connection.token,
        connection.server_version,
        connection.authentication,
        connection.host_key.describe(),
        connection.verification.describe()
    );
    if let Some(timeout) = connection.idle_timeout {
        text.push_str(&format!(
            "\nThe connection closes after {} without a tool call.",
            format_duration(timeout)
        ));
    }
    if let Some(banner) = &connection.banner
        && !banner.is_empty()
    {
        text.push_str("\n--- banner (sent by the server) ---\n");
        text.push_str(banner);
        text.push_str("\n--- end of banner ---");
    }
    Ok(text)
}

/// Describe why the handshake failed, with the host key when the server got far enough to present
/// one. `legacy` is whether older algorithms were already offered.
fn handshake_failure(
    facts: &Mutex<HandshakeFacts>,
    target: &Target,
    error: &russh::Error,
    legacy: bool,
) -> ToolError {
    let facts = lock(facts);
    match &facts.host_key {
        Some((report, Verdict::Refused(reason))) => {
            ToolError::new(format!("Host key refused. {reason}\n{}", report.describe()))
        }
        _ => {
            let remedy = match error {
                russh::Error::NoCommonAlgo { .. } if !legacy => {
                    ". The server may need older algorithms: pass allow_legacy_algorithms."
                }
                _ => "",
            };
            ToolError::new(format!(
                "Could not connect to {}:{}: {error}{remedy}",
                target.host, target.port
            ))
        }
    }
}

fn method_names(methods: &MethodSet) -> String {
    let names: Vec<&str> = methods
        .iter()
        .filter(|method| **method != MethodKind::None)
        .map(<&str>::from)
        .collect();
    if names.is_empty() {
        "none".to_owned()
    } else {
        names.join(", ")
    }
}

/// A login method `authenticate` can try.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Method {
    PublicKey,
    Password,
    KeyboardInteractive,
}

impl Method {
    fn name(self) -> &'static str {
        match self {
            Self::PublicKey => "publickey",
            Self::Password => "password",
            Self::KeyboardInteractive => "keyboard-interactive",
        }
    }
}

/// How one login attempt went.
enum Attempt {
    Success,
    /// Accepted, but the server requires more: it now offers these methods.
    Partial(MethodSet),
    /// Not accepted, for the reason given; the server now offers these methods.
    Failed(String, MethodSet),
}

impl Attempt {
    fn from_result(result: client::AuthResult, method: Method, rejected: &str) -> Self {
        match result {
            client::AuthResult::Success => Self::Success,
            client::AuthResult::Failure {
                remaining_methods,
                partial_success: true,
            } => Self::Partial(remaining_methods),
            client::AuthResult::Failure {
                remaining_methods, ..
            } => Self::Failed(format!("{} ({rejected})", method.name()), remaining_methods),
        }
    }
}

/// The credentials a connect was given.
struct Credentials<'a> {
    key: Option<Arc<PrivateKey>>,
    certificate: Option<Certificate>,
    password: Option<&'a str>,
    /// Sign with an RSA key using SHA-1 when the server does not list SHA-2 RSA signatures.
    allow_sha1_rsa: bool,
}

/// Signs login requests with the private key a connect was given. A certificate login goes
/// through it because russh signs one itself only under the SHA-1 RSA name, which OpenSSH 8.8
/// and later refuse.
struct KeySigner(Arc<PrivateKey>);

/// Why a login request could not be signed.
#[derive(Debug)]
struct SigningError(String);

impl From<russh::SendError> for SigningError {
    fn from(error: russh::SendError) -> Self {
        Self(error.to_string())
    }
}

impl russh::Signer for KeySigner {
    type Error = SigningError;

    async fn auth_sign(
        &mut self,
        _identity: &AgentIdentity,
        hash: Option<HashAlg>,
        mut to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, SigningError> {
        let failed = |error: &dyn std::fmt::Display| SigningError(error.to_string());
        let signature = match self.0.key_data() {
            KeypairData::Rsa(keypair) => (keypair, hash).try_sign(&to_sign),
            keypair => keypair.try_sign(&to_sign),
        }
        .map_err(|error| failed(&error))?;
        let mut blob = Vec::new();
        signature
            .encode(&mut blob)
            .map_err(|error| failed(&error))?;
        blob.encode(&mut to_sign).map_err(|error| failed(&error))?;
        Ok(to_sign)
    }
}

/// Log in with what was given. Each round tries a method the server offers at that point and
/// that has not been tried: the key (with its certificate), the password, then keyboard-
/// interactive questions answered with the password. A method accepted with more required
/// ("partial success") counts, and the server's new list decides the next round, so a server
/// that requires two methods in turn (`AuthenticationMethods password,publickey`) is satisfied.
async fn authenticate(
    handle: &mut SshHandle,
    target: &Target,
    credentials: Credentials<'_>,
) -> Result<String, ToolError> {
    let user = target.user.as_str();
    let failed = |error: russh::Error| ToolError::new(format!("Logging in failed: {error}"));
    let mut methods = match handle.authenticate_none(user).await.map_err(failed)? {
        client::AuthResult::Success => return Ok("no authentication".to_owned()),
        client::AuthResult::Failure {
            remaining_methods, ..
        } => remaining_methods,
    };
    let offered_at_start = method_names(&methods);
    let mut available = Vec::new();
    if credentials.key.is_some() {
        available.push(Method::PublicKey);
    }
    if credentials.password.is_some() {
        available.extend([Method::Password, Method::KeyboardInteractive]);
    }
    let mut tried: Vec<Method> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    let mut succeeded: Vec<&str> = Vec::new();
    loop {
        let next = available.iter().copied().find(|method| {
            !tried.contains(method)
                && methods.contains(&match method {
                    Method::PublicKey => MethodKind::PublicKey,
                    Method::Password => MethodKind::Password,
                    Method::KeyboardInteractive => MethodKind::KeyboardInteractive,
                })
        });
        let Some(method) = next else {
            break;
        };
        tried.push(method);
        let attempt = match method {
            Method::PublicKey => {
                let Some(key) = &credentials.key else {
                    continue;
                };
                let is_rsa = key.algorithm().is_rsa();
                // The best SHA-2 hash the server lists for RSA signatures, if it lists one.
                let listed_sha2 = if is_rsa {
                    handle
                        .best_supported_rsa_hash()
                        .await
                        .map_err(failed)?
                        .flatten()
                } else {
                    None
                };
                // SHA-1 (no hash) only when allowed: a server that lists no SHA-2 RSA signatures
                // may still take them.
                let hash = match listed_sha2 {
                    Some(hash) => Some(hash),
                    None if !is_rsa || credentials.allow_sha1_rsa => None,
                    None => Some(HashAlg::Sha256),
                };
                let result = match credentials.certificate.clone() {
                    Some(certificate) => handle
                        .authenticate_certificate_with(
                            user,
                            certificate,
                            hash,
                            &mut KeySigner(Arc::clone(key)),
                        )
                        .await
                        .map_err(|error| {
                            ToolError::new(format!("Signing the login failed: {}", error.0))
                        })?,
                    None => handle
                        .authenticate_publickey(
                            user,
                            PrivateKeyWithHashAlg::new(Arc::clone(key), hash),
                        )
                        .await
                        .map_err(failed)?,
                };
                let rejected = if is_rsa && listed_sha2.is_none() && !credentials.allow_sha1_rsa {
                    "the key was not accepted; the server does not list SHA-2 RSA signatures, so it may need allow_legacy_algorithms"
                } else {
                    "the key was not accepted"
                };
                Attempt::from_result(result, method, rejected)
            }
            Method::Password => {
                let Some(password) = credentials.password else {
                    continue;
                };
                let result = handle
                    .authenticate_password(user, password)
                    .await
                    .map_err(failed)?;
                Attempt::from_result(result, method, "rejected")
            }
            Method::KeyboardInteractive => {
                let Some(password) = credentials.password else {
                    continue;
                };
                keyboard_interactive(handle, user, password, &methods).await?
            }
        };
        match attempt {
            Attempt::Success => {
                succeeded.push(method.name());
                return Ok(succeeded.join(" + "));
            }
            Attempt::Partial(remaining) => {
                succeeded.push(method.name());
                methods = remaining;
            }
            Attempt::Failed(description, remaining) => {
                failures.push(description);
                methods = remaining;
            }
        }
    }
    if credentials.key.is_some() && !tried.contains(&Method::PublicKey) {
        failures.push("publickey (the server does not offer it)".to_owned());
    }
    if credentials.password.is_some()
        && !tried.contains(&Method::Password)
        && !tried.contains(&Method::KeyboardInteractive)
    {
        failures.push("password (the server does not offer it)".to_owned());
    }

    let mut message = format!("Logging in to {} failed.", target.describe());
    message.push_str(&format!(" The server accepts: {offered_at_start}."));
    if !succeeded.is_empty() {
        message.push_str(&format!(
            " Accepted but not enough on its own: {}; the server now asks for: {}.",
            succeeded.join(", "),
            method_names(&methods)
        ));
    }
    if available.is_empty() {
        message.push_str(
            " No credentials were given: pass private_key, private_key_file or password.",
        );
    } else if !failures.is_empty() {
        message.push_str(&format!(" Tried: {}.", failures.join("; ")));
    }
    Err(ToolError::new(message))
}

/// A keyboard-interactive question as a result quotes it: escaped and shortened, since the server
/// chose the text.
fn quoted_question(prompt: &str) -> String {
    let question: String = prompt.trim().chars().take(QUESTION_CHARS).collect();
    format!("{question:?}")
}

/// Answer the server's keyboard-interactive questions with the password. A question shown with
/// echo on (a username or a code to type visibly) cannot be answered with a password, so the
/// login stops there and the result names the question. `methods` is what the server offered
/// before, kept when the exchange is abandoned.
async fn keyboard_interactive(
    handle: &mut SshHandle,
    user: &str,
    password: &str,
    methods: &MethodSet,
) -> Result<Attempt, ToolError> {
    let failed = |error: russh::Error| ToolError::new(format!("Logging in failed: {error}"));
    let mut response = handle
        .authenticate_keyboard_interactive_start(user, None::<String>)
        .await
        .map_err(failed)?;
    let mut questions: Vec<String> = Vec::new();
    let mut rounds = 0;
    loop {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(Attempt::Success),
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success: true,
            } => return Ok(Attempt::Partial(remaining_methods)),
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods, ..
            } => {
                let asked = if questions.is_empty() {
                    String::new()
                } else {
                    format!(", asked {}", questions.join(", "))
                };
                return Ok(Attempt::Failed(
                    format!("keyboard-interactive (rejected{asked})"),
                    remaining_methods,
                ));
            }
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                for prompt in &prompts {
                    let question = quoted_question(&prompt.prompt);
                    if !questions.contains(&question) {
                        questions.push(question);
                    }
                }
                if let Some(visible) = prompts.iter().find(|prompt| prompt.echo) {
                    return Ok(Attempt::Failed(
                        format!(
                            "keyboard-interactive (the server asked {}, which a password cannot answer)",
                            quoted_question(&visible.prompt)
                        ),
                        methods.clone(),
                    ));
                }
                if !prompts.is_empty() {
                    rounds += 1;
                    if rounds > KEYBOARD_INTERACTIVE_ROUNDS {
                        return Ok(Attempt::Failed(
                            format!(
                                "keyboard-interactive (kept asking: {})",
                                questions.join(", ")
                            ),
                            methods.clone(),
                        ));
                    }
                }
                let answers = vec![password.to_owned(); prompts.len()];
                response = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await
                    .map_err(failed)?;
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unguessable_and_distinct() {
        let first = new_token().unwrap();
        let second = new_token().unwrap();
        assert!(first.starts_with("conn_"));
        assert_eq!(first.len(), "conn_".len() + 32);
        assert_ne!(first, second);
    }

    #[test]
    fn checkable_key_types_move_to_the_front() {
        let preferred =
            prefer_checkable_keys(Preferred::default(), &[Algorithm::Rsa { hash: None }]);
        assert!(matches!(preferred.key.first(), Some(Algorithm::Rsa { .. })));
        assert_eq!(preferred.key.len(), Preferred::default().key.len());
    }

    #[test]
    fn an_encrypted_key_needs_its_passphrase_and_the_error_says_so() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key");
        let generated = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "correct passphrase", "-f"])
            .arg(&path)
            .status();
        if !generated.is_ok_and(|status| status.success()) {
            eprintln!("ssh-keygen is not installed; skipping");
            return;
        }
        let material = Material::File(path.display().to_string());
        let missing = load_private_key(&material, None).unwrap_err();
        assert!(
            missing.message().contains("pass private_key_passphrase"),
            "{missing}"
        );
        let wrong = load_private_key(&material, Some("wrong")).unwrap_err();
        assert!(
            wrong.message().contains("passphrase may be wrong"),
            "{wrong}"
        );
        assert!(load_private_key(&material, Some("correct passphrase")).is_ok());
        let pkcs8 = directory.path().join("pkcs8");
        let generated = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ecdsa", "-m", "PKCS8", "-N", "secret", "-f"])
            .arg(&pkcs8)
            .status();
        assert!(generated.is_ok_and(|status| status.success()));
        let pkcs8 = Material::File(pkcs8.display().to_string());
        let missing = load_private_key(&pkcs8, None).unwrap_err();
        assert!(
            missing.message().contains("pass private_key_passphrase"),
            "{missing}"
        );
        assert!(load_private_key(&pkcs8, Some("secret")).is_ok());
        let not_a_key = Material::Content("not a key".to_owned());
        let refused = load_private_key(&not_a_key, None).unwrap_err();
        assert!(
            !refused.message().contains("not a key"),
            "contents are never echoed: {refused}"
        );
    }

    /// An encrypted PKCS#8 key as LibreSSL writes it, and so `ssh-keygen -m PKCS8` on macOS and
    /// Windows: PBKDF2 with HMAC-SHA1. A throwaway ECDSA key whose passphrase is `secret`.
    const PKCS8_SHA1_KEY: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIHmMFEGCSqGSIb3DQEFDTBEMCMGCSqGSIb3DQEFDDAWBBAYAGEHoDZa8vZ0h01w\nbNHqAgIIADAdBglghkgBZQMEAQIEEApCvCeSu1O3QNWQrOEoUgcEgZCmoNC8dOTR\nUDX79+8BvvZ5iHWMhcWFYSWKbzonM9NVV8eqtD5PIjEHZqsLhp3UtbcbanOjyCqP\n8BiiZjUSu4zmla3k9A8vxxBQQwyZukqJLVkDMPoZYMYaNmSgGVpPDY3JeezbMokf\nJppbyXBkQ2JYvXIMZP9e0T0szcO39uEYblZgIKdLHeZrT8nZSeH8M04=\n-----END ENCRYPTED PRIVATE KEY-----";

    #[test]
    fn an_encrypted_pkcs8_key_from_libressl_is_read_with_its_passphrase() {
        let material = Material::Content(PKCS8_SHA1_KEY.to_owned());
        let missing = load_private_key(&material, None).unwrap_err();
        assert!(
            missing.message().contains("pass private_key_passphrase"),
            "{missing}"
        );
        assert!(load_private_key(&material, Some("secret")).is_ok());
    }

    #[test]
    fn legacy_algorithms_come_after_the_defaults() {
        let defaults = Preferred::default();
        let legacy = legacy_preferences(Preferred::default());
        assert_eq!(legacy.kex.first(), defaults.kex.first());
        assert!(legacy.kex.contains(&kex::DH_G14_SHA1));
        assert!(legacy.cipher.contains(&cipher::AES_128_CBC));
        assert!(legacy.key.contains(&Algorithm::Dsa));
    }
}
