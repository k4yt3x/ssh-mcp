//! The MCP server: tool definitions, argument schemas and the dispatch from each tool to the module
//! that does the work.

use std::{sync::Arc, time::Duration};

use rmcp::{
    RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig},
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

use crate::{
    connection::{ConnectRequest, ConnectionUse, Material, Registry, Target},
    exec, forward,
    output::{Progress, ToolError},
    sftp, shell,
};

/// Which optional tool groups the server offers, set by its command-line flags.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Features {
    pub(crate) sftp: bool,
    pub(crate) local_forwarding: bool,
    pub(crate) remote_forwarding: bool,
    pub(crate) dynamic_forwarding: bool,
}

const SFTP_TOOLS: [&str; 5] = ["read_file", "write_file", "edit_file", "upload", "download"];

const INSTRUCTIONS: &str = "SSH connections, shells, files and forwarding. Call connect first: it returns a connection token that every other tool takes. Tokens keep connections apart, so keep yours, hand it to whoever should use the connection, and expect a connection to close after an hour without a tool call (idle_timeout_seconds). Nothing from this machine's ~/.ssh is used: connect takes the key or password, and a host key check. Use exec for one-off commands. Use shell_open and shell_run for anything that keeps state (cd, export, activated environments), runs long, or asks questions. Every shell result starts with the shell's state in brackets and carries only output no earlier result returned. Local paths must be absolute or start with ~/.";

const DEFAULT_PORT: u16 = 22;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(3600);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_RUN_WAIT: Duration = Duration::from_secs(30);
const DEFAULT_SEND_WAIT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_OUTPUT_BYTES: usize = 64 * 1024;
const DEFAULT_COLUMNS: u16 = 200;
const DEFAULT_ROWS: u16 = 50;

/// A credential argument. Its value never appears in a validation error or a debug print, so a
/// password sent as a number is refused without the number being echoed back.
struct Secret(String);

impl Secret {
    fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Secret(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match serde_json::Value::deserialize(deserializer)? {
            serde_json::Value::String(text) => Ok(Self(text)),
            _ => Err(serde::de::Error::custom("a credential must be a string")),
        }
    }
}

impl JsonSchema for Secret {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        String::schema_name()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        String::json_schema(generator)
    }

    fn inline_schema() -> bool {
        true
    }
}

/// Remove the `format` keyword from a schema and every schema inside it. schemars marks integer
/// and number fields with formats such as `uint16` and `double`, which JSON Schema does not
/// define and which some model providers' tool validators refuse; the `minimum` and `maximum`
/// beside them keep the bounds.
fn strip_formats(schema: &mut schemars::Schema) {
    schema.remove("format");
    schemars::transform::transform_subschemas(&mut strip_formats, schema);
}

/// One host key fingerprint or several.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(untagged)]
#[schemars(inline)]
enum Fingerprints {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(transform = strip_formats)]
struct ConnectArguments {
    /// Hostname or IP address.
    host: String,
    /// Account to log in as.
    user: String,
    /// Default 22.
    port: Option<u16>,
    /// Private key text (OpenSSH, PEM or PuTTY format). Use instead of private_key_file.
    private_key: Option<Secret>,
    /// Path of a private key file on this machine.
    private_key_file: Option<String>,
    /// Decrypts an encrypted private key here; it is never sent to the server.
    private_key_passphrase: Option<Secret>,
    /// OpenSSH certificate text for the private key. Use instead of certificate_file.
    certificate: Option<String>,
    /// Path of an OpenSSH certificate file (`*-cert.pub`) for the private key.
    certificate_file: Option<String>,
    /// Password for password and keyboard-interactive login.
    password: Option<Secret>,
    /// The expected host key: a `SHA256:` fingerprint or a public key line, or a list of them.
    host_key_fingerprint: Option<Fingerprints>,
    /// Path of a known_hosts file on this machine to check the host key against. It is only read.
    known_hosts_file: Option<String>,
    /// Accept a host key that cannot be checked: a host known_hosts_file does not list, or any key
    /// when no check is given. A host listed with a different key is still refused.
    accept_new_host_key: Option<bool>,
    /// Token of an open connection to tunnel through, as a jump host.
    via: Option<String>,
    /// Also offer older algorithms (SHA-1, CBC ciphers, DSA keys) for servers that need them.
    allow_legacy_algorithms: Option<bool>,
    /// Seconds without a tool call before the connection closes; 0 keeps it open. Default 3600.
    idle_timeout_seconds: Option<u64>,
    /// Seconds allowed for connecting and for logging in, each. Default 15.
    connect_timeout_seconds: Option<f64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(transform = strip_formats)]
struct ConnectionArguments {
    /// The token connect returned.
    connection: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(transform = strip_formats)]
struct ExecArguments {
    /// The token connect returned.
    connection: String,
    /// Command line, run by the account's login shell.
    command: String,
    /// Text written to the command's stdin, which is then closed. Without it, stdin is closed at
    /// once.
    stdin: Option<String>,
    /// Default 30.
    timeout_seconds: Option<f64>,
    /// The most bytes of each stream to return; beyond it, the start and end are kept. Default
    /// 65536.
    max_output_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(transform = strip_formats)]
struct ShellOpenArguments {
    /// The token connect returned.
    connection: String,
    /// Program to run instead of the login shell, such as `bash` or `python3`.
    command: Option<String>,
    /// Leave the terminal as the program sets it up: no prompt detection or exit codes.
    raw: Option<bool>,
    /// Terminal width. Default 200.
    columns: Option<u16>,
    /// Terminal height. Default 50.
    rows: Option<u16>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(transform = strip_formats)]
struct ShellRunArguments {
    /// The token connect returned.
    connection: String,
    /// The shell number shell_open returned.
    shell: u32,
    /// Command to run; may span several lines.
    command: String,
    /// Seconds to wait for it to finish before returning `still running`. Default 30.
    wait_seconds: Option<f64>,
    /// The most output to return; the rest waits for shell_read. Default 65536.
    max_output_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(transform = strip_formats)]
struct ShellSendArguments {
    /// The token connect returned.
    connection: String,
    /// The shell number shell_open returned.
    shell: u32,
    /// Text typed as is; end it with a newline or press enter to submit a line.
    text: Option<String>,
    /// Keys pressed after the text: enter, tab, escape, backspace, delete, insert, space, up,
    /// down, left, right, home, end, page_up, page_down, f1 to f12, or ctrl+ a letter.
    keys: Option<Vec<String>>,
    /// Regex to wait for in the output that follows the input.
    until: Option<String>,
    /// Most seconds to wait. Default 10.
    wait_seconds: Option<f64>,
    /// The most output to return; the rest waits for shell_read. Default 65536.
    max_output_bytes: Option<usize>,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[schemars(inline)]
enum ViewArgument {
    Auto,
    Stream,
    Screen,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(transform = strip_formats)]
struct ShellReadArguments {
    /// The token connect returned.
    connection: String,
    /// The shell number shell_open returned.
    shell: u32,
    /// Regex to wait for in the output not yet returned.
    until: Option<String>,
    /// Most seconds to wait for the running command to finish, until to match, or new output to
    /// settle. Default 0: return at once.
    wait_seconds: Option<f64>,
    /// `stream`: new output as text. `screen`: the rendered terminal. `auto` (default): the screen
    /// while a full-screen program runs, the stream otherwise.
    view: Option<ViewArgument>,
    /// The most output to return; the rest waits for the next read. Default 65536.
    max_output_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(transform = strip_formats)]
struct ShellCloseArguments {
    /// The token connect returned.
    connection: String,
    /// The shell number shell_open returned.
    shell: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(transform = strip_formats)]
struct ReadFileArguments {
    /// The token connect returned.
    connection: String,
    /// Remote path; relative paths and `~/` start at the login directory.
    path: String,
    /// First line to return, counted from 1. Default 1.
    offset: Option<usize>,
    /// Most lines to return. Default 2000.
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(transform = strip_formats)]
struct WriteFileArguments {
    /// The token connect returned.
    connection: String,
    /// Remote path; relative paths and `~/` start at the login directory.
    path: String,
    /// The file's new content.
    content: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(transform = strip_formats)]
struct EditFileArguments {
    /// The token connect returned.
    connection: String,
    /// Remote path; relative paths and `~/` start at the login directory.
    path: String,
    /// Exact text to replace, including whitespace.
    old_string: String,
    /// Replacement text.
    new_string: String,
    /// Replace every match instead of requiring exactly one.
    replace_all: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(transform = strip_formats)]
struct UploadArguments {
    /// The token connect returned.
    connection: String,
    /// File or folder on this machine.
    local_path: String,
    /// Full remote path to write, not the folder to put it in.
    remote_path: String,
    /// Replace what exists at remote_path; a folder is merged into.
    overwrite: Option<bool>,
    /// Octal permissions for a single uploaded file, such as `0755`. Default: the local file's.
    mode: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(transform = strip_formats)]
struct DownloadArguments {
    /// The token connect returned.
    connection: String,
    /// Remote file or folder; relative paths and `~/` start at the login directory.
    remote_path: String,
    /// Full path to write on this machine; its parent folder must exist.
    local_path: String,
    /// Replace what exists at local_path; a folder is merged into.
    overwrite: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(transform = strip_formats)]
struct ForwardLocalArguments {
    /// The token connect returned.
    connection: String,
    /// Host to reach from the server.
    remote_host: String,
    /// Port to reach from the server.
    remote_port: u16,
    /// Port to listen on at 127.0.0.1 here; 0 (default) picks a free one.
    local_port: Option<u16>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(transform = strip_formats)]
struct ForwardRemoteArguments {
    /// The token connect returned.
    connection: String,
    /// Port for the server to listen on; 0 lets it pick.
    remote_port: u16,
    /// Host to reach from this machine.
    local_host: String,
    /// Port to reach from this machine.
    local_port: u16,
    /// Address the server listens on. Default `localhost`; the server's GatewayPorts setting
    /// decides whether others are allowed.
    remote_bind_address: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(transform = strip_formats)]
struct ForwardDynamicArguments {
    /// The token connect returned.
    connection: String,
    /// Port to listen on at 127.0.0.1 here; 0 (default) picks a free one.
    local_port: Option<u16>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(transform = strip_formats)]
struct ForwardCloseArguments {
    /// The token connect returned.
    connection: String,
    /// The forward number the forward tool returned.
    forward: u32,
}

/// The longest timeout or wait accepted, so a deadline computed from it cannot overflow.
const MAX_SECONDS: f64 = 366.0 * 24.0 * 3600.0;

/// Convert a seconds argument to a duration, refusing values that are not a number of seconds
/// from 0 to a year.
fn seconds(argument: &str, value: Option<f64>, default: Duration) -> Result<Duration, ToolError> {
    match value {
        None => Ok(default),
        Some(value) if value <= MAX_SECONDS => Duration::try_from_secs_f64(value).map_err(|_| {
            ToolError::new(format!("{argument} must be a number of seconds, 0 or more"))
        }),
        Some(_) => Err(ToolError::new(format!("{argument} must be at most a year"))),
    }
}

fn output_limit(value: Option<usize>) -> Result<usize, ToolError> {
    match value {
        None => Ok(DEFAULT_MAX_OUTPUT_BYTES),
        Some(0) => Err(ToolError::new("max_output_bytes must be at least 1")),
        Some(value) => Ok(value),
    }
}

fn parse_mode(mode: Option<&str>) -> Result<Option<u32>, ToolError> {
    mode.map(|text| {
        let digits = text.trim().trim_start_matches("0o");
        u32::from_str_radix(digits, 8)
            .ok()
            .filter(|mode| *mode <= 0o7777)
            .ok_or_else(|| {
                ToolError::new(format!(
                    "mode \"{text}\" is not octal permissions such as 0644"
                ))
            })
    })
    .transpose()
}

fn finish(result: Result<String, ToolError>) -> CallToolResult {
    match result {
        Ok(text) => CallToolResult::success(vec![ContentBlock::text(text)]),
        Err(error) => CallToolResult::error(vec![ContentBlock::text(error.message())]),
    }
}

/// Pick the one material a pair of mutually exclusive arguments gives.
fn material(
    content: Option<String>,
    file: Option<String>,
    content_name: &str,
    file_name: &str,
) -> Result<Option<Material>, ToolError> {
    match (content, file) {
        (Some(_), Some(_)) => Err(ToolError::new(format!(
            "{content_name} and {file_name} cannot be combined; pass one"
        ))),
        (Some(content), None) => Ok(Some(Material::Content(content))),
        (None, Some(file)) => Ok(Some(Material::File(file))),
        (None, None) => Ok(None),
    }
}

/// The MCP server.
#[derive(Clone)]
pub(crate) struct SshServer {
    registry: Arc<Registry>,
    tool_router: ToolRouter<Self>,
}

impl SshServer {
    /// A server offering the tools `features` enables. Starts the idle-connection reaper, so it
    /// must be called inside the runtime.
    pub(crate) fn new(features: Features) -> Self {
        let registry = Arc::new(Registry::default());
        registry.spawn_reaper();
        let mut tool_router = Self::tool_router();
        if !features.sftp {
            for name in SFTP_TOOLS {
                tool_router.remove_route(name);
            }
        }
        if !features.local_forwarding {
            tool_router.remove_route("forward_local");
        }
        if !features.remote_forwarding {
            tool_router.remove_route("forward_remote");
        }
        if !features.dynamic_forwarding {
            tool_router.remove_route("forward_dynamic");
        }
        if !(features.local_forwarding || features.remote_forwarding || features.dynamic_forwarding)
        {
            tool_router.remove_route("forward_close");
        }
        Self {
            registry,
            tool_router,
        }
    }

    fn connection(&self, token: &str) -> Result<ConnectionUse, ToolError> {
        self.registry.get(token)
    }

    async fn sftp_session(
        &self,
        token: &str,
        cancel: &CancellationToken,
    ) -> Result<(ConnectionUse, Arc<russh_sftp::client::SftpSession>), ToolError> {
        let connection = self.connection(token)?;
        let session = sftp::session(&connection.handle, &connection.sftp, cancel).await?;
        Ok((connection, session))
    }
}

#[tool_router]
impl SshServer {
    #[tool(
        description = "Open an SSH connection and log in. Returns a connection token every other tool needs; it cannot be recovered, so keep it. Nothing from this machine's ~/.ssh is used; key, certificate and known_hosts files are read only where the arguments name them. The host key must be checked with host_key_fingerprint or known_hosts_file, or accepted unchecked with accept_new_host_key; the result always shows the key, with a known_hosts line to record.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn connect(
        &self,
        Parameters(arguments): Parameters<ConnectArguments>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let result = async {
            let private_key = material(
                arguments.private_key.map(Secret::into_inner),
                arguments.private_key_file,
                "private_key",
                "private_key_file",
            )?;
            let certificate = material(
                arguments.certificate,
                arguments.certificate_file,
                "certificate",
                "certificate_file",
            )?;
            // The jump host stays in use, so it is not closed as idle, until the connect ends.
            let jump = arguments
                .via
                .as_deref()
                .map(|token| self.connection(token))
                .transpose()?;
            let host_key_fingerprints = match arguments.host_key_fingerprint {
                None => Vec::new(),
                Some(Fingerprints::One(fingerprint)) => vec![fingerprint],
                Some(Fingerprints::Many(fingerprints)) => fingerprints,
            };
            let idle_timeout = match arguments.idle_timeout_seconds {
                Some(0) => None,
                Some(seconds) => Some(Duration::from_secs(seconds)),
                None => Some(DEFAULT_IDLE_TIMEOUT),
            };
            let request = ConnectRequest {
                target: Target {
                    host: arguments.host,
                    port: arguments.port.unwrap_or(DEFAULT_PORT),
                    user: arguments.user,
                },
                private_key,
                private_key_passphrase: arguments.private_key_passphrase.map(Secret::into_inner),
                certificate,
                password: arguments.password.map(Secret::into_inner),
                host_key_fingerprints,
                known_hosts_file: arguments.known_hosts_file,
                accept_new_host_key: arguments.accept_new_host_key.unwrap_or(false),
                via: jump.as_ref().map(ConnectionUse::shared),
                allow_legacy_algorithms: arguments.allow_legacy_algorithms.unwrap_or(false),
                idle_timeout,
                connect_timeout: seconds(
                    "connect_timeout_seconds",
                    arguments.connect_timeout_seconds,
                    DEFAULT_CONNECT_TIMEOUT,
                )?,
            };
            tokio::select! {
                result = crate::connection::connect(&self.registry, request) => result,
                () = context.ct.cancelled() => Err(ToolError::new("The connect was cancelled.")),
            }
        }
        .await;
        finish(result)
    }

    #[tool(
        description = "Describe a connection: where it logs in, the server, its host key, idle time left, and its open shells and forwards.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn connection_status(
        &self,
        Parameters(arguments): Parameters<ConnectionArguments>,
    ) -> CallToolResult {
        finish(
            self.connection(&arguments.connection)
                .map(|connection| connection.describe()),
        )
    }

    #[tool(
        description = "Close a connection with its shells, forwards and SFTP session. Connections tunneled through it are closed too.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn disconnect(
        &self,
        Parameters(arguments): Parameters<ConnectionArguments>,
    ) -> CallToolResult {
        finish(self.registry.disconnect(&arguments.connection).await)
    }

    #[tool(
        description = "Run a command on its own channel without a terminal: stdout and stderr stay apart, the exit code is exact, and nothing carries over between calls. A command still running at the timeout, or when the call is canceled, gets TERM, then KILL; one that prints over 64 MiB is stopped. Use a shell for state (cd, export) or interactive programs, and for long work: a client may end a call early, often after a few minutes.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = true
        )
    )]
    async fn exec(
        &self,
        Parameters(arguments): Parameters<ExecArguments>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let result = async {
            let connection = self.connection(&arguments.connection)?;
            let request = exec::ExecRequest {
                command: arguments.command,
                stdin: arguments.stdin,
                timeout: seconds(
                    "timeout_seconds",
                    arguments.timeout_seconds,
                    DEFAULT_EXEC_TIMEOUT,
                )?,
                max_output_bytes: output_limit(arguments.max_output_bytes)?,
            };
            let mut progress = Progress::from_context(&context);
            exec::run(&connection.handle, request, &context.ct, &mut progress).await
        }
        .await;
        finish(result)
    }

    #[tool(
        description = "Start a persistent shell in a terminal. A program that answers the POSIX shell setup (the login shell, sh, bash, zsh) is managed: shell_run reports exit codes, results say when it is back at its prompt, and pagers are set to cat. Other programs (fish, device CLIs, REPLs) and raw=true get a plain terminal, driven with shell_send and shell_read.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn shell_open(
        &self,
        Parameters(arguments): Parameters<ShellOpenArguments>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let result = async {
            let connection = self.connection(&arguments.connection)?;
            let request = shell::OpenRequest {
                command: arguments.command,
                raw: arguments.raw.unwrap_or(false),
                columns: arguments.columns.unwrap_or(DEFAULT_COLUMNS),
                rows: arguments.rows.unwrap_or(DEFAULT_ROWS),
            };
            shell::open(&connection.handle, &connection.shells, request, &context.ct).await
        }
        .await;
        finish(result)
    }

    #[tool(
        description = "Run a command in a managed shell, where cd, export and activated environments persist. Returns its output and exit code, or `still running` after wait_seconds; the command keeps running, so follow it with shell_read. A client may end a call early, often after a few minutes, so for long work keep waits to a few minutes and poll with shell_read. Its input is the terminal: answer its prompts with shell_send.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = true
        )
    )]
    async fn shell_run(
        &self,
        Parameters(arguments): Parameters<ShellRunArguments>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let result = async {
            let connection = self.connection(&arguments.connection)?;
            let request = shell::RunRequest {
                command: arguments.command,
                wait: seconds("wait_seconds", arguments.wait_seconds, DEFAULT_RUN_WAIT)?,
                max_output_bytes: output_limit(arguments.max_output_bytes)?,
            };
            let mut progress = Progress::from_context(&context);
            shell::run(
                &connection.shells,
                arguments.shell,
                request,
                &context.ct,
                &mut progress,
            )
            .await
        }
        .await;
        finish(result)
    }

    #[tool(
        description = "Type into a shell: the text as is, then the keys. Answers prompts, drives REPLs and full-screen programs, interrupts with ctrl+c. Returns once output has been quiet for a moment, until matches, or wait_seconds runs out.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = true
        )
    )]
    async fn shell_send(
        &self,
        Parameters(arguments): Parameters<ShellSendArguments>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let result = async {
            let connection = self.connection(&arguments.connection)?;
            let request = shell::SendRequest {
                text: arguments.text,
                keys: arguments.keys.unwrap_or_default(),
                until: arguments.until,
                wait: seconds("wait_seconds", arguments.wait_seconds, DEFAULT_SEND_WAIT)?,
                max_output_bytes: output_limit(arguments.max_output_bytes)?,
            };
            let mut progress = Progress::from_context(&context);
            shell::send(
                &connection.shells,
                arguments.shell,
                request,
                &context.ct,
                &mut progress,
            )
            .await
        }
        .await;
        finish(result)
    }

    #[tool(
        description = "Return a shell's state and the output not yet returned. With wait_seconds, waits until the running command finishes, until matches, new output settles, or the time runs out. A call ended early by the client leaves the output for the next read.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn shell_read(
        &self,
        Parameters(arguments): Parameters<ShellReadArguments>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let result = async {
            let connection = self.connection(&arguments.connection)?;
            let request = shell::ReadRequest {
                until: arguments.until,
                wait: seconds("wait_seconds", arguments.wait_seconds, Duration::ZERO)?,
                view: match arguments.view.unwrap_or(ViewArgument::Auto) {
                    ViewArgument::Auto => shell::View::Auto,
                    ViewArgument::Stream => shell::View::Stream,
                    ViewArgument::Screen => shell::View::Screen,
                },
                max_output_bytes: output_limit(arguments.max_output_bytes)?,
            };
            let mut progress = Progress::from_context(&context);
            shell::read(
                &connection.shells,
                arguments.shell,
                request,
                &context.ct,
                &mut progress,
            )
            .await
        }
        .await;
        finish(result)
    }

    #[tool(
        description = "Close a shell, hanging up everything running in it, and return output not yet read.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn shell_close(
        &self,
        Parameters(arguments): Parameters<ShellCloseArguments>,
    ) -> CallToolResult {
        let result = async {
            let connection = self.connection(&arguments.connection)?;
            shell::close(&connection.shells, arguments.shell).await
        }
        .await;
        finish(result)
    }

    #[tool(
        description = "Read lines of a remote UTF-8 text file over SFTP: files up to 64 MiB, at most 256 KiB of lines per result.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn read_file(
        &self,
        Parameters(arguments): Parameters<ReadFileArguments>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let result = async {
            let (_connection, session) = self
                .sftp_session(&arguments.connection, &context.ct)
                .await?;
            let request = sftp::ReadRequest {
                path: arguments.path,
                offset: match arguments.offset {
                    Some(0) => return Err(ToolError::new("offset counts lines from 1")),
                    Some(offset) => offset,
                    None => 1,
                },
                limit: match arguments.limit {
                    Some(0) => return Err(ToolError::new("limit must be at least 1")),
                    Some(limit) => limit,
                    None => sftp::DEFAULT_READ_LINES,
                },
            };
            sftp::read_file(&session, request).await
        }
        .await;
        finish(result)
    }

    #[tool(
        description = "Create a remote text file or overwrite it in place over SFTP, keeping an existing file's permissions and writing through symlinks.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = true
        )
    )]
    async fn write_file(
        &self,
        Parameters(arguments): Parameters<WriteFileArguments>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let result = async {
            let (_connection, session) = self
                .sftp_session(&arguments.connection, &context.ct)
                .await?;
            sftp::write_file(&session, &arguments.path, &arguments.content).await
        }
        .await;
        finish(result)
    }

    #[tool(
        description = "Replace old_string with new_string in a remote text file over SFTP. old_string must match exactly once unless replace_all is set.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = true
        )
    )]
    async fn edit_file(
        &self,
        Parameters(arguments): Parameters<EditFileArguments>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let result = async {
            let (_connection, session) = self
                .sftp_session(&arguments.connection, &context.ct)
                .await?;
            let request = sftp::EditRequest {
                path: arguments.path,
                old_string: arguments.old_string,
                new_string: arguments.new_string,
                replace_all: arguments.replace_all.unwrap_or(false),
            };
            sftp::edit_file(&session, request).await
        }
        .await;
        finish(result)
    }

    #[tool(
        description = "Copy a file or folder from this machine to the server over SFTP. Folders copy recursively, symlinks stay symlinks, and permissions are kept. Each file is written under a temporary name and renamed into place.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = true
        )
    )]
    async fn upload(
        &self,
        Parameters(arguments): Parameters<UploadArguments>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let result = async {
            let mode = parse_mode(arguments.mode.as_deref())?;
            let (connection, session) = self
                .sftp_session(&arguments.connection, &context.ct)
                .await?;
            let request = sftp::UploadRequest {
                local_path: arguments.local_path,
                remote_path: arguments.remote_path,
                overwrite: arguments.overwrite.unwrap_or(false),
                mode,
                reversed_symlink_arguments: connection.is_openssh(),
            };
            let mut progress = Progress::from_context(&context);
            sftp::upload(&session, request, &context.ct, &mut progress).await
        }
        .await;
        finish(result)
    }

    #[tool(
        description = "Copy a file or folder from the server to this machine over SFTP. Folders copy recursively, symlinks stay symlinks, and permissions are kept. Writes on this machine only under local_path, each file under a temporary name renamed into place.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = true
        )
    )]
    async fn download(
        &self,
        Parameters(arguments): Parameters<DownloadArguments>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let result = async {
            let (connection, session) = self
                .sftp_session(&arguments.connection, &context.ct)
                .await?;
            let request = sftp::DownloadRequest {
                remote_path: arguments.remote_path,
                local_path: arguments.local_path,
                overwrite: arguments.overwrite.unwrap_or(false),
            };
            let mut progress = Progress::from_context(&context);
            sftp::download(
                &connection.handle,
                &session,
                request,
                &context.ct,
                &mut progress,
            )
            .await
        }
        .await;
        finish(result)
    }

    #[tool(
        description = "Listen on 127.0.0.1 here and carry each connection to remote_host:remote_port from the server, like ssh -L.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn forward_local(
        &self,
        Parameters(arguments): Parameters<ForwardLocalArguments>,
    ) -> CallToolResult {
        let result = async {
            let connection = self.connection(&arguments.connection)?;
            forward::open_local(
                Arc::clone(&connection.handle),
                &connection.forwards,
                &connection.closed,
                arguments.remote_host,
                arguments.remote_port,
                arguments.local_port.unwrap_or(0),
            )
            .await
        }
        .await;
        finish(result)
    }

    #[tool(
        description = "Have the server listen on remote_port and carry each connection to local_host:local_port from this machine, like ssh -R.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn forward_remote(
        &self,
        Parameters(arguments): Parameters<ForwardRemoteArguments>,
    ) -> CallToolResult {
        let result = async {
            let connection = self.connection(&arguments.connection)?;
            forward::open_remote(
                &connection.handle,
                &connection.forwards,
                &connection.remote_forward_targets,
                arguments
                    .remote_bind_address
                    .unwrap_or_else(|| "localhost".to_owned()),
                arguments.remote_port,
                arguments.local_host,
                arguments.local_port,
            )
            .await
        }
        .await;
        finish(result)
    }

    #[tool(
        description = "Run a SOCKS5 proxy on 127.0.0.1 here whose connections are made from the server, like ssh -D.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn forward_dynamic(
        &self,
        Parameters(arguments): Parameters<ForwardDynamicArguments>,
    ) -> CallToolResult {
        let result = async {
            let connection = self.connection(&arguments.connection)?;
            forward::open_dynamic(
                Arc::clone(&connection.handle),
                &connection.forwards,
                &connection.closed,
                arguments.local_port.unwrap_or(0),
            )
            .await
        }
        .await;
        finish(result)
    }

    #[tool(
        description = "Stop a forward.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn forward_close(
        &self,
        Parameters(arguments): Parameters<ForwardCloseArguments>,
    ) -> CallToolResult {
        let result = async {
            let connection = self.connection(&arguments.connection)?;
            forward::close(
                &connection.handle,
                &connection.forwards,
                &connection.remote_forward_targets,
                arguments.forward,
            )
            .await
        }
        .await;
        finish(result)
    }
}

#[cfg(test)]
mod tests;

#[tool_handler(router = self.tool_router)]
impl ServerHandler for SshServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(INSTRUCTIONS)
    }
}
