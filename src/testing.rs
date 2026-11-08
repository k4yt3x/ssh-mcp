//! Test fixtures: random keys, an in-process SSH server with scripted commands, and a real OpenSSH
//! server where one is installed.

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use russh::{
    Channel, ChannelId, ChannelMsg, MethodKind, MethodSet,
    keys::{
        PrivateKey,
        ssh_key::{PublicKey, private::Ed25519Keypair},
    },
    server::{self, Auth, Msg, Session},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
};

/// A new random Ed25519 key.
pub(crate) fn random_private_key() -> PrivateKey {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("randomness");
    PrivateKey::from(Ed25519Keypair::from_seed(&seed))
}

/// How the in-process server lets clients log in.
#[derive(Clone, Default)]
pub(crate) struct Logins {
    /// The password `password` login accepts.
    pub(crate) password: Option<String>,
    /// The key `publickey` login accepts.
    pub(crate) public_key: Option<PublicKey>,
    /// The answer keyboard-interactive login accepts for its one hidden question.
    pub(crate) keyboard_interactive: Option<String>,
    /// Ask a visible question first in keyboard-interactive login, which a password cannot answer.
    pub(crate) keyboard_interactive_visible_question: bool,
    /// Require the key and then the password (`AuthenticationMethods publickey,password`).
    pub(crate) key_then_password: bool,
    /// Require the password and then the key (`AuthenticationMethods password,publickey`),
    /// offering only the password at first.
    pub(crate) password_then_key: bool,
    /// Accept anyone without credentials.
    pub(crate) no_authentication: bool,
    /// The banner sent before login.
    pub(crate) banner: Option<String>,
}

/// An SSH server in this process, on a random port of 127.0.0.1. It runs scripted commands rather
/// than a shell:
///
/// - `echo TEXT`: prints TEXT and exits 0
/// - `fail CODE`: prints `failure` to stderr and exits CODE
/// - `cat`: prints its stdin back after it closes, then exits 0
/// - `sleep`: runs until a signal and reports it as the exit signal
/// - `stubborn`: ignores TERM, exits on KILL
/// - `flood BYTES`: prints BYTES bytes of `x`
///
/// It also opens `direct-tcpip` channels to 127.0.0.1 and serves `tcpip-forward` requests.
pub(crate) struct TestServer {
    pub(crate) port: u16,
    pub(crate) host_key: PublicKey,
}

impl TestServer {
    pub(crate) async fn start(logins: Logins) -> Self {
        let host_key = random_private_key();
        let public = host_key.public_key().clone();
        let mut methods = MethodSet::empty();
        if logins.password.is_some() {
            methods.push(MethodKind::Password);
        }
        if logins.public_key.is_some() && !logins.password_then_key {
            methods.push(MethodKind::PublicKey);
        }
        if logins.keyboard_interactive.is_some() {
            methods.push(MethodKind::KeyboardInteractive);
        }
        let config = Arc::new(server::Config {
            keys: vec![host_key],
            methods,
            auth_rejection_time: Duration::from_millis(1),
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..server::Config::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("address").port();
        let logins = Arc::new(logins);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let handler = TestHandler {
                    logins: Arc::clone(&logins),
                    key_accepted: false,
                    password_accepted: false,
                    signals: Arc::new(Mutex::new(HashMap::new())),
                };
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    if let Ok(session) = server::run_stream(config, socket, handler).await {
                        let _ = session.await;
                    }
                });
            }
        });
        Self {
            port,
            host_key: public,
        }
    }
}

struct TestHandler {
    logins: Arc<Logins>,
    key_accepted: bool,
    password_accepted: bool,
    signals: Arc<Mutex<HashMap<ChannelId, tokio::sync::mpsc::UnboundedSender<russh::Sig>>>>,
}

fn only(method: MethodKind) -> Option<MethodSet> {
    let mut methods = MethodSet::empty();
    methods.push(method);
    Some(methods)
}

impl server::Handler for TestHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        if self.logins.no_authentication {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        let correct = self.logins.password.as_deref() == Some(password);
        if correct && self.logins.password_then_key {
            self.password_accepted = true;
            return Ok(Auth::Reject {
                proceed_with_methods: only(MethodKind::PublicKey),
                partial_success: true,
            });
        }
        if correct && (!self.logins.key_then_password || self.key_accepted) {
            Ok(Auth::Accept)
        } else if self.logins.key_then_password && !self.key_accepted {
            Ok(Auth::Reject {
                proceed_with_methods: only(MethodKind::PublicKey),
                partial_success: false,
            })
        } else {
            Ok(Auth::reject())
        }
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        let accepted = self
            .logins
            .public_key
            .as_ref()
            .is_some_and(|expected| expected.key_data() == key.public_key.key_data());
        if !accepted || (self.logins.password_then_key && !self.password_accepted) {
            return Ok(Auth::reject());
        }
        if self.logins.key_then_password {
            self.key_accepted = true;
            return Ok(Auth::Reject {
                proceed_with_methods: only(MethodKind::Password),
                partial_success: true,
            });
        }
        Ok(Auth::Accept)
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        response: Option<server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        let Some(expected) = self.logins.keyboard_interactive.clone() else {
            return Ok(Auth::reject());
        };
        match response {
            None => {
                let prompts: Vec<(std::borrow::Cow<'static, str>, bool)> =
                    if self.logins.keyboard_interactive_visible_question {
                        vec![("Verification code: ".into(), true)]
                    } else {
                        vec![("Password: ".into(), false)]
                    };
                Ok(Auth::Partial {
                    name: "".into(),
                    instructions: "".into(),
                    prompts: prompts.into(),
                })
            }
            Some(mut answers) => {
                let answer = answers.next().map(|bytes| bytes.to_vec());
                if answer.as_deref() == Some(expected.as_bytes()) {
                    Ok(Auth::Accept)
                } else {
                    Ok(Auth::reject())
                }
            }
        }
    }

    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        Ok(self.logins.banner.clone())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let (signal_sender, signal_receiver) = tokio::sync::mpsc::unbounded_channel();
        self.signals
            .lock()
            .await
            .insert(channel.id(), signal_sender);
        reply.accept().await;
        tokio::spawn(run_scripted(channel, session.handle(), signal_receiver));
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: russh::Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(sender) = self.signals.lock().await.get(&channel) {
            let _ = sender.send(signal);
        }
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let address = format!("{host_to_connect}:{port_to_connect}");
        match TcpStream::connect(address).await {
            Ok(mut socket) => {
                reply.accept().await;
                tokio::spawn(async move {
                    let mut stream = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut socket).await;
                });
            }
            Err(_) => drop(reply),
        }
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let Ok(requested) = u16::try_from(*port) else {
            return Ok(false);
        };
        let Ok(listener) = TcpListener::bind(("127.0.0.1", requested)).await else {
            return Ok(false);
        };
        let Ok(local) = listener.local_addr() else {
            return Ok(false);
        };
        *port = u32::from(local.port());
        let handle = session.handle();
        let address = address.to_owned();
        let bound_port = *port;
        tokio::spawn(async move {
            while let Ok((mut socket, peer)) = listener.accept().await {
                let handle = handle.clone();
                let address = address.clone();
                tokio::spawn(async move {
                    if let Ok(channel) = handle
                        .channel_open_forwarded_tcpip(
                            address,
                            bound_port,
                            peer.ip().to_string(),
                            u32::from(peer.port()),
                        )
                        .await
                    {
                        let mut stream = channel.into_stream();
                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut socket).await;
                    }
                });
            }
        });
        Ok(true)
    }
}

async fn run_scripted(
    mut channel: Channel<Msg>,
    handle: server::Handle,
    mut signals: tokio::sync::mpsc::UnboundedReceiver<russh::Sig>,
) {
    let mut terminal = None;
    let start = loop {
        match channel.wait().await {
            Some(ChannelMsg::RequestPty {
                term,
                col_width,
                row_height,
                ..
            }) => terminal = Some((term, col_width, row_height)),
            Some(ChannelMsg::RequestShell { .. }) => break None,
            Some(ChannelMsg::Exec { command, .. }) => {
                break Some(String::from_utf8_lossy(&command).into_owned());
            }
            Some(_) => {}
            None => return,
        }
    };
    if let Some((term, columns, rows)) = terminal {
        #[cfg(unix)]
        run_in_terminal(channel, handle, start, &term, columns, rows).await;
        #[cfg(not(unix))]
        {
            let _ = (term, columns, rows, handle);
            let _ = channel.close().await;
        }
        return;
    }
    let Some(command) = start else {
        let _ = channel.close().await;
        return;
    };
    let (program, argument) = command.split_once(' ').unwrap_or((command.as_str(), ""));
    match program {
        "echo" => {
            let _ = channel.data(format!("{argument}\n").as_bytes()).await;
            let _ = channel.exit_status(0).await;
        }
        "fail" => {
            let _ = channel.extended_data(1, &b"failure\n"[..]).await;
            let _ = channel.exit_status(argument.parse().unwrap_or(1)).await;
        }
        "cat" => {
            let mut input = Vec::new();
            loop {
                match channel.wait().await {
                    Some(ChannelMsg::Data { data }) => input.extend_from_slice(&data),
                    Some(ChannelMsg::Eof) | None => break,
                    Some(_) => {}
                }
            }
            let _ = channel.data(&input[..]).await;
            let _ = channel.exit_status(0).await;
        }
        "sleep" | "stubborn" => loop {
            let Some(signal) = signals.recv().await else {
                return;
            };
            if program == "stubborn" && matches!(signal, russh::Sig::TERM) {
                continue;
            }
            let _ = handle
                .exit_signal_request(channel.id(), signal, false, String::new(), String::new())
                .await;
            break;
        },
        "flood" => {
            let mut remaining: usize = argument.parse().unwrap_or(0);
            let chunk = vec![b'x'; 32 * 1024];
            while remaining > 0 {
                let size = remaining.min(chunk.len());
                if channel.data(&chunk[..size]).await.is_err() {
                    return;
                }
                remaining -= size;
            }
            let _ = channel.exit_status(0).await;
        }
        _ => {
            let _ = channel.extended_data(1, &b"unknown command\n"[..]).await;
            let _ = channel.exit_status(127).await;
        }
    }
    let _ = channel.eof().await;
    let _ = channel.close().await;
}

/// Serve a channel that asked for a terminal the way sshd does: the login shell (`$SHELL`, started
/// as a login shell) or `sh -c COMMAND`, on a real pseudo-terminal of this machine.
#[cfg(unix)]
async fn run_in_terminal(
    channel: Channel<Msg>,
    handle: server::Handle,
    command: Option<String>,
    term: &str,
    columns: u32,
    rows: u32,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let id = channel.id();
    let close = |handle: server::Handle| async move {
        let _ = handle.eof(id).await;
        let _ = handle.close(id).await;
    };
    let Ok((pty, pts)) = pty_process::open() else {
        close(handle).await;
        return;
    };
    let size = pty_process::Size::new(
        u16::try_from(rows).unwrap_or(50),
        u16::try_from(columns).unwrap_or(200),
    );
    let _ = pty.resize(size);
    let program = match &command {
        Some(line) => pty_process::Command::new("/bin/sh").args(["-c", line.as_str()]),
        None => {
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_owned());
            let name = Path::new(&shell)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "sh".to_owned());
            pty_process::Command::new(&shell).arg0(format!("-{name}"))
        }
    };
    // An empty home, so the shells read none of the developer's startup files and write the test
    // commands to no history file.
    let Ok(home) = tempfile::tempdir() else {
        close(handle).await;
        return;
    };
    // zsh offers its new-user setup menu in a home with no startup files.
    let _ = std::fs::write(home.path().join(".zshrc"), "");
    let program = program
        .env("TERM", term)
        .env("HOME", home.path())
        .env("ZDOTDIR", home.path())
        .env("HISTFILE", "/dev/null")
        .env_remove("ENV")
        .env_remove("BASH_ENV");
    let Ok(mut child) = program.spawn(pts) else {
        close(handle).await;
        return;
    };
    let (mut reader, mut writer) = pty.into_split();
    let (mut channel_reader, channel_writer) = channel.split();
    let output = tokio::spawn(async move {
        let mut buffer = [0u8; 8192];
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if channel_writer.data(&buffer[..read]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    let status = loop {
        tokio::select! {
            message = channel_reader.wait() => match message {
                Some(ChannelMsg::Data { data }) => {
                    if writer.write_all(&data).await.is_err() {
                        break None;
                    }
                }
                Some(ChannelMsg::Close) | None => {
                    let _ = child.start_kill();
                    break None;
                }
                Some(_) => {}
            },
            status = child.wait() => break status.ok(),
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(1), output).await;
    drop(home);
    if let Some(code) = status.and_then(|status| status.code()) {
        let _ = handle
            .exit_status_request(id, u32::try_from(code).unwrap_or(1))
            .await;
    }
    close(handle).await;
}

/// A real OpenSSH server for this user on a random port of 127.0.0.1. Login is by the key in
/// `client_key_file`; SFTP is OpenSSH's own.
pub(crate) struct Sshd {
    pub(crate) port: u16,
    pub(crate) client_key_file: PathBuf,
    pub(crate) host_key: PublicKey,
    pub(crate) user: String,
    pub(crate) directory: tempfile::TempDir,
    child: std::process::Child,
}

impl Sshd {
    /// Start the server, or return `None` with the reason printed when it cannot run here. With
    /// `SSH_MCP_REQUIRE_SSHD` set, as CI sets it where sshd is installed, that is a failure
    /// instead, so the tests that need it cannot pass by skipping.
    pub(crate) async fn start() -> Option<Self> {
        match Self::try_start().await {
            Ok(sshd) => Some(sshd),
            Err(reason) => {
                assert!(
                    std::env::var_os("SSH_MCP_REQUIRE_SSHD").is_none(),
                    "sshd is required: {reason}"
                );
                eprintln!("{reason}; skipping");
                None
            }
        }
    }

    async fn try_start() -> Result<Self, String> {
        let binary = ["/usr/sbin/sshd", "/usr/bin/sshd", "/usr/local/sbin/sshd"]
            .into_iter()
            .map(Path::new)
            .find(|path| path.exists())
            .ok_or("sshd is not installed")?;
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .map_err(|_| "the user name is unknown (no USER or LOGNAME)")?;
        let directory = tempfile::tempdir().expect("temporary directory");
        let host_key = random_private_key();
        let client_key = random_private_key();
        let host_key_file = directory.path().join("host_key");
        let client_key_file = directory.path().join("client_key");
        let authorized_keys = directory.path().join("authorized_keys");
        write_private_key(&host_key_file, &host_key);
        write_private_key(&client_key_file, &client_key);
        std::fs::write(
            &authorized_keys,
            client_key.public_key().to_openssh().expect("public key"),
        )
        .expect("authorized_keys");
        let port = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            probe.local_addr().expect("address").port()
        };
        let config = directory.path().join("sshd_config");
        std::fs::write(
            &config,
            format!(
                "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile none\nAuthorizedKeysFile {}\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nSubsystem sftp internal-sftp\nLogLevel ERROR\n",
                host_key_file.display(),
                authorized_keys.display()
            ),
        )
        .expect("sshd_config");
        let mut child = std::process::Command::new(binary)
            .args(["-D", "-e", "-f"])
            .arg(&config)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|error| format!("sshd could not be started: {error}"))?;
        let address: SocketAddr = format!("127.0.0.1:{port}").parse().expect("address");
        for _ in 0..100 {
            if TcpStream::connect(address).await.is_ok() {
                return Ok(Self {
                    port,
                    client_key_file,
                    host_key: host_key.public_key().clone(),
                    user,
                    directory,
                    child,
                });
            }
            if let Ok(Some(status)) = child.try_wait() {
                return Err(format!("sshd exited at once ({status})"));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let _ = child.kill();
        let _ = child.wait();
        Err(format!("sshd did not listen on port {port} within 5s"))
    }
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_private_key(path: &Path, key: &PrivateKey) {
    let text = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .expect("private key");
    std::fs::write(path, text.as_bytes()).expect("key file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("mode");
    }
}
