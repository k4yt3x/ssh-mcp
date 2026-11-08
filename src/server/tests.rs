//! End-to-end tests: an MCP client calls the server's tools over an in-memory pipe, against the
//! in-process SSH server and, where `sshd` is installed, a real OpenSSH server.

use std::time::Duration;

use rmcp::{RoleClient, ServiceExt, model::CallToolRequestParams, service::RunningService};
use russh::keys::ssh_key::HashAlg;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use super::{Features, SshServer};
use crate::testing::{Logins, Sshd, TestServer, random_private_key};

const ALL_FEATURES: Features = Features {
    sftp: true,
    local_forwarding: true,
    remote_forwarding: true,
    dynamic_forwarding: true,
};

struct Harness {
    client: RunningService<RoleClient, ()>,
}

impl Harness {
    async fn start(features: Features) -> Self {
        let (server_side, client_side) = tokio::io::duplex(4 * 1024 * 1024);
        let server = SshServer::new(features);
        tokio::spawn(async move {
            if let Ok(running) = server.serve(server_side).await {
                let _ = running.waiting().await;
            }
        });
        let client = ().serve(client_side).await.expect("client");
        Self { client }
    }

    async fn tool_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .client
            .list_all_tools()
            .await
            .expect("tools")
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect();
        names.sort();
        names
    }

    /// Call a tool, returning whether the result is an error and its text.
    async fn call(&self, name: &str, arguments: Value) -> (bool, String) {
        let Value::Object(arguments) = arguments else {
            panic!("arguments must be an object");
        };
        let result = self
            .client
            .call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(arguments))
            .await
            .expect("tool call");
        let text = result
            .content
            .iter()
            .filter_map(|block| block.as_text().map(|text| text.text.clone()))
            .collect::<Vec<_>>()
            .join("\n");
        (result.is_error.unwrap_or(false), text)
    }

    async fn ok(&self, name: &str, arguments: Value) -> String {
        let (is_error, text) = self.call(name, arguments).await;
        assert!(!is_error, "{name} failed: {text}");
        text
    }

    async fn error(&self, name: &str, arguments: Value) -> String {
        let (is_error, text) = self.call(name, arguments).await;
        assert!(is_error, "{name} unexpectedly succeeded: {text}");
        text
    }

    /// Connect and return the token.
    async fn connect(&self, arguments: Value) -> String {
        let text = self.ok("connect", arguments).await;
        token_from(&text)
    }
}

fn token_from(text: &str) -> String {
    text.lines()
        .find_map(|line| line.strip_prefix("connection: "))
        .expect("token line")
        .to_owned()
}

fn password_server_logins() -> Logins {
    Logins {
        password: Some("hunter2".to_owned()),
        ..Logins::default()
    }
}

fn fingerprint(server: &TestServer) -> String {
    server.host_key.fingerprint(HashAlg::Sha256).to_string()
}

async fn password_connection(harness: &Harness, server: &TestServer) -> String {
    harness
        .connect(json!({
            "host": "127.0.0.1",
            "port": server.port,
            "user": "agent",
            "password": "hunter2",
            "host_key_fingerprint": fingerprint(server),
        }))
        .await
}

/// A TCP server on 127.0.0.1 that writes back whatever it reads.
async fn echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("address").port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                while let Ok(read) = socket.read(&mut buffer).await {
                    if read == 0 || socket.write_all(&buffer[..read]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

async fn round_trip(port: u16, message: &[u8]) -> Vec<u8> {
    let mut socket = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    socket.write_all(message).await.expect("write");
    let mut reply = vec![0u8; message.len()];
    tokio::time::timeout(Duration::from_secs(10), socket.read_exact(&mut reply))
        .await
        .expect("reply in time")
        .expect("read");
    reply
}

fn forward_port(text: &str) -> u16 {
    let after = text.split("127.0.0.1:").nth(1).expect("port in result");
    after
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .expect("port")
}

#[tokio::test]
async fn optional_tools_follow_the_flags() {
    let defaults = Harness::start(Features {
        sftp: true,
        local_forwarding: false,
        remote_forwarding: false,
        dynamic_forwarding: false,
    })
    .await;
    let names = defaults.tool_names().await;
    assert!(names.contains(&"download".to_owned()));
    assert!(!names.iter().any(|name| name.starts_with("forward_")));

    let no_sftp = Harness::start(Features {
        sftp: false,
        local_forwarding: true,
        remote_forwarding: false,
        dynamic_forwarding: false,
    })
    .await;
    let names = no_sftp.tool_names().await;
    for removed in [
        "read_file",
        "write_file",
        "edit_file",
        "upload",
        "download",
        "forward_remote",
        "forward_dynamic",
    ] {
        assert!(!names.contains(&removed.to_owned()), "{removed} is offered");
    }
    assert!(names.contains(&"forward_local".to_owned()));
    assert!(names.contains(&"forward_close".to_owned()));

    let all = Harness::start(ALL_FEATURES).await;
    assert_eq!(all.tool_names().await.len(), 18);
}

#[tokio::test]
async fn a_host_key_must_be_checked_or_explicitly_accepted() {
    let server = TestServer::start(password_server_logins()).await;
    let harness = Harness::start(ALL_FEATURES).await;
    let base =
        json!({"host": "127.0.0.1", "port": server.port, "user": "agent", "password": "hunter2"});

    let refused = harness.error("connect", base.clone()).await;
    assert!(refused.contains("No host key check was given"), "{refused}");
    assert!(
        refused.contains(&fingerprint(&server)),
        "the refusal shows the key: {refused}"
    );

    let mut accepting = base.clone();
    accepting["accept_new_host_key"] = json!(true);
    let text = harness.ok("connect", accepting).await;
    assert!(text.contains("not verified: accepted as new"), "{text}");
    assert!(
        text.contains(&format!("[127.0.0.1]:{} ssh-ed25519 ", server.port)),
        "{text}"
    );

    let mut wrong = base.clone();
    wrong["host_key_fingerprint"] = json!(
        random_private_key()
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string()
    );
    let refused = harness.error("connect", wrong).await;
    assert!(
        refused.contains("does not match host_key_fingerprint"),
        "{refused}"
    );

    let mut right = base;
    right["host_key_fingerprint"] = json!([fingerprint(&server)]);
    let text = harness.ok("connect", right).await;
    assert!(
        text.contains("verified against host_key_fingerprint"),
        "{text}"
    );
}

#[tokio::test]
async fn a_known_hosts_file_refuses_a_changed_key_even_when_accepting_new_hosts() {
    let server = TestServer::start(password_server_logins()).await;
    let harness = Harness::start(ALL_FEATURES).await;
    let directory = tempfile::tempdir().expect("temporary directory");
    let known_hosts = directory.path().join("known_hosts");
    let base = json!({
        "host": "127.0.0.1",
        "port": server.port,
        "user": "agent",
        "password": "hunter2",
        "known_hosts_file": known_hosts.display().to_string(),
        "accept_new_host_key": true,
    });

    std::fs::write(&known_hosts, "").expect("known_hosts");
    let text = harness.ok("connect", base.clone()).await;
    assert!(text.contains("not verified: the host is not in"), "{text}");

    let listed = format!(
        "[127.0.0.1]:{} {}\n",
        server.port,
        server.host_key.to_openssh().expect("key")
    );
    std::fs::write(&known_hosts, &listed).expect("known_hosts");
    let text = harness.ok("connect", base.clone()).await;
    assert!(text.contains("verified against"), "{text}");

    let changed = format!(
        "[127.0.0.1]:{} {}\n",
        server.port,
        random_private_key().public_key().to_openssh().expect("key")
    );
    std::fs::write(&known_hosts, changed).expect("known_hosts");
    let refused = harness.error("connect", base.clone()).await;
    assert!(refused.contains("does not match the key"), "{refused}");

    std::fs::remove_file(&known_hosts).expect("remove");
    let refused = harness.error("connect", base).await;
    assert!(refused.contains("could not be read"), "{refused}");
}

#[tokio::test]
async fn logins_use_exactly_what_was_given() {
    let key = random_private_key();
    let key_text = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .expect("key")
        .to_string();
    let harness = Harness::start(ALL_FEATURES).await;

    let server = TestServer::start(Logins {
        password: Some("hunter2".to_owned()),
        public_key: Some(key.public_key().clone()),
        banner: Some("Authorized use only".to_owned()),
        ..Logins::default()
    })
    .await;
    let base = json!({"host": "127.0.0.1", "port": server.port, "user": "agent", "host_key_fingerprint": fingerprint(&server)});

    let mut with_key = base.clone();
    with_key["private_key"] = json!(key_text);
    let text = harness.ok("connect", with_key).await;
    assert!(text.contains("Logged in with: publickey"), "{text}");
    assert!(
        text.contains("Authorized use only"),
        "the banner is shown: {text}"
    );

    let mut wrong_password = base.clone();
    wrong_password["password"] = json!("wrong");
    let refused = harness.error("connect", wrong_password).await;
    assert!(refused.contains("password (rejected)"), "{refused}");
    assert!(
        refused.contains("The server accepts: password, publickey")
            || refused.contains("The server accepts: publickey, password"),
        "{refused}"
    );

    let refused = harness.error("connect", base.clone()).await;
    assert!(refused.contains("No credentials were given"), "{refused}");

    let mut both_keys = base;
    both_keys["private_key"] = json!(key_text);
    both_keys["private_key_file"] = json!("/nonexistent");
    let refused = harness.error("connect", both_keys).await;
    assert!(refused.contains("cannot be combined"), "{refused}");
}

#[tokio::test]
async fn keyboard_interactive_is_answered_with_the_password_unless_the_question_is_visible() {
    let harness = Harness::start(ALL_FEATURES).await;
    let server = TestServer::start(Logins {
        keyboard_interactive: Some("hunter2".to_owned()),
        ..Logins::default()
    })
    .await;
    let arguments = json!({"host": "127.0.0.1", "port": server.port, "user": "agent", "password": "hunter2", "host_key_fingerprint": fingerprint(&server)});
    let text = harness.ok("connect", arguments).await;
    assert!(text.contains("keyboard-interactive"), "{text}");

    let visible = TestServer::start(Logins {
        keyboard_interactive: Some("hunter2".to_owned()),
        keyboard_interactive_visible_question: true,
        ..Logins::default()
    })
    .await;
    let arguments = json!({"host": "127.0.0.1", "port": visible.port, "user": "agent", "password": "hunter2", "host_key_fingerprint": fingerprint(&visible)});
    let refused = harness.error("connect", arguments).await;
    assert!(refused.contains("Verification code"), "{refused}");
}

#[tokio::test]
async fn a_key_accepted_with_more_required_continues_with_the_password() {
    let key = random_private_key();
    let harness = Harness::start(ALL_FEATURES).await;
    let server = TestServer::start(Logins {
        password: Some("hunter2".to_owned()),
        public_key: Some(key.public_key().clone()),
        key_then_password: true,
        ..Logins::default()
    })
    .await;
    let key_text = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .expect("key")
        .to_string();
    let arguments = json!({"host": "127.0.0.1", "port": server.port, "user": "agent", "private_key": key_text, "password": "hunter2", "host_key_fingerprint": fingerprint(&server)});
    let text = harness.ok("connect", arguments.clone()).await;
    assert!(
        text.contains("Logged in with: publickey + password"),
        "{text}"
    );

    let mut key_only = arguments;
    key_only.as_object_mut().expect("object").remove("password");
    let refused = harness.error("connect", key_only).await;
    assert!(
        refused.contains("Accepted but not enough on its own: publickey"),
        "{refused}"
    );
}

#[tokio::test]
async fn exec_reports_exit_codes_and_keeps_streams_apart() {
    let server = TestServer::start(password_server_logins()).await;
    let harness = Harness::start(ALL_FEATURES).await;
    let token = password_connection(&harness, &server).await;

    let text = harness
        .ok(
            "exec",
            json!({"connection": token, "command": "echo hello"}),
        )
        .await;
    assert!(text.starts_with("[exit code 0 after"), "{text}");
    assert!(text.ends_with("--- stdout ---\nhello"), "{text}");
    assert!(!text.contains("stderr"), "{text}");

    let text = harness
        .ok("exec", json!({"connection": token, "command": "fail 3"}))
        .await;
    assert!(text.starts_with("[exit code 3 after"), "{text}");
    assert!(text.ends_with("--- stderr ---\nfailure"), "{text}");

    let text = harness
        .ok(
            "exec",
            json!({"connection": token, "command": "cat", "stdin": "piped input"}),
        )
        .await;
    assert!(text.contains("piped input"), "{text}");

    let text = harness
        .ok(
            "exec",
            json!({"connection": token, "command": "flood 100000", "max_output_bytes": 100}),
        )
        .await;
    assert!(text.contains("omitted"), "{text}");
    assert!(text.len() < 1000, "{text}");
}

#[tokio::test]
async fn a_command_past_its_timeout_gets_term_then_kill() {
    let server = TestServer::start(password_server_logins()).await;
    let harness = Harness::start(ALL_FEATURES).await;
    let token = password_connection(&harness, &server).await;

    let text = harness
        .ok(
            "exec",
            json!({"connection": token, "command": "sleep", "timeout_seconds": 0.2}),
        )
        .await;
    assert!(text.contains("timed out after 0.2s (sent TERM;"), "{text}");
    assert!(text.contains("killed by signal TERM"), "{text}");

    let text = harness
        .ok(
            "exec",
            json!({"connection": token, "command": "stubborn", "timeout_seconds": 0.2}),
        )
        .await;
    assert!(text.contains("sent TERM, then KILL"), "{text}");
    assert!(text.contains("killed by signal KILL"), "{text}");

    // More stdin than the server's window holds, to a command that never reads it.
    let text = tokio::time::timeout(
        Duration::from_secs(20),
        harness.ok(
            "exec",
            json!({"connection": token, "command": "sleep", "stdin": "x".repeat(8 * 1024 * 1024), "timeout_seconds": 0.5}),
        ),
    )
    .await
    .expect("exec returned despite unread stdin");
    assert!(text.contains("timed out after 0.5s"), "{text}");
}

#[tokio::test]
async fn a_token_is_the_only_way_to_a_connection() {
    let server = TestServer::start(password_server_logins()).await;
    let harness = Harness::start(ALL_FEATURES).await;
    let token = password_connection(&harness, &server).await;

    let refused = harness
        .error(
            "exec",
            json!({"connection": "conn_0000", "command": "echo x"}),
        )
        .await;
    assert!(
        refused.contains("No open connection has that token"),
        "{refused}"
    );

    let status = harness
        .ok("connection_status", json!({"connection": token}))
        .await;
    assert!(
        status.contains("Connection to agent@127.0.0.1:"),
        "{status}"
    );

    harness.ok("disconnect", json!({"connection": token})).await;
    let refused = harness
        .error("exec", json!({"connection": token, "command": "echo x"}))
        .await;
    assert!(
        refused.contains("No open connection has that token"),
        "{refused}"
    );
}

#[tokio::test]
async fn forwards_carry_connections_both_ways_and_stop_when_closed() {
    let server = TestServer::start(password_server_logins()).await;
    let harness = Harness::start(ALL_FEATURES).await;
    let token = password_connection(&harness, &server).await;
    let echo = echo_server().await;

    let text = harness
        .ok(
            "forward_local",
            json!({"connection": token, "remote_host": "127.0.0.1", "remote_port": echo}),
        )
        .await;
    let local_port = forward_port(&text);
    assert_eq!(round_trip(local_port, b"through -L").await, b"through -L");

    let text = harness
        .ok("forward_remote", json!({"connection": token, "remote_port": 0, "local_host": "127.0.0.1", "local_port": echo}))
        .await;
    let remote_port: u16 = text
        .split("port ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|port| port.parse().ok())
        .expect("remote port");
    assert_eq!(round_trip(remote_port, b"through -R").await, b"through -R");

    let text = harness
        .ok("forward_dynamic", json!({"connection": token}))
        .await;
    let socks_port = forward_port(&text);
    let mut socket = TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .expect("connect");
    socket.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut choice = [0u8; 2];
    socket.read_exact(&mut choice).await.expect("method");
    assert_eq!(choice, [5, 0]);
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&echo.to_be_bytes());
    socket.write_all(&request).await.expect("request");
    let mut reply = [0u8; 10];
    socket.read_exact(&mut reply).await.expect("reply");
    assert_eq!(reply[1], 0, "SOCKS success");
    socket.write_all(b"through -D").await.expect("data");
    let mut echoed = [0u8; 10];
    socket.read_exact(&mut echoed).await.expect("echo");
    assert_eq!(&echoed, b"through -D");

    let status = harness
        .ok("connection_status", json!({"connection": token}))
        .await;
    assert!(status.contains("forward 1: local"), "{status}");
    assert!(status.contains("forward 3: dynamic"), "{status}");

    harness
        .ok("forward_close", json!({"connection": token, "forward": 1}))
        .await;
    assert!(
        TcpStream::connect(("127.0.0.1", local_port)).await.is_err(),
        "the listener stopped"
    );
    harness
        .error("forward_close", json!({"connection": token, "forward": 1}))
        .await;
}

#[tokio::test]
async fn a_connection_through_a_jump_host_works_and_ends_with_it() {
    let jump = TestServer::start(password_server_logins()).await;
    let target = TestServer::start(password_server_logins()).await;
    let harness = Harness::start(ALL_FEATURES).await;
    let jump_token = password_connection(&harness, &jump).await;
    let text = harness
        .ok(
            "connect",
            json!({
                "host": "127.0.0.1",
                "port": target.port,
                "user": "agent",
                "password": "hunter2",
                "host_key_fingerprint": fingerprint(&target),
                "via": jump_token,
            }),
        )
        .await;
    let target_token = token_from(&text);
    let text = harness
        .ok(
            "exec",
            json!({"connection": target_token, "command": "echo through"}),
        )
        .await;
    assert!(text.contains("through"), "{text}");
    let status = harness
        .ok("connection_status", json!({"connection": target_token}))
        .await;
    assert!(status.contains("Through: agent@127.0.0.1:"), "{status}");

    let text = harness
        .ok("disconnect", json!({"connection": jump_token}))
        .await;
    assert!(
        text.contains("1 connection tunneled through it was closed too"),
        "{text}"
    );
    assert!(
        !text.contains(&format!(":{}", target.port)),
        "other connections are not named: {text}"
    );
    let (is_error, text) = harness
        .call(
            "exec",
            json!({"connection": target_token, "command": "echo x"}),
        )
        .await;
    assert!(is_error && text.contains("No open connection"), "{text}");
}

/// A harness connected to a real OpenSSH server, or `None` when `sshd` cannot run here.
async fn sshd_connection() -> Option<(Sshd, Harness, String)> {
    let sshd = Sshd::start().await?;
    let harness = Harness::start(ALL_FEATURES).await;
    let token = harness
        .connect(json!({
            "host": "127.0.0.1",
            "port": sshd.port,
            "user": sshd.user,
            "private_key_file": sshd.client_key_file.display().to_string(),
            "host_key_fingerprint": sshd.host_key.fingerprint(HashAlg::Sha256).to_string(),
        }))
        .await;
    Some((sshd, harness, token))
}

/// A harness connected to the in-process server, whose terminals run real shells of this machine.
#[cfg(unix)]
async fn terminal_connection() -> (TestServer, Harness, String) {
    let server = TestServer::start(password_server_logins()).await;
    let harness = Harness::start(ALL_FEATURES).await;
    let token = password_connection(&harness, &server).await;
    (server, harness, token)
}

#[cfg(unix)]
#[tokio::test]
async fn a_managed_shell_keeps_state_and_reports_exit_codes() {
    let (_server, harness, token) = terminal_connection().await;
    let installed = |name: &str| {
        ["/bin", "/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"]
            .iter()
            .any(|directory| std::path::Path::new(directory).join(name).exists())
    };
    let mut programs = vec![None];
    programs.extend(
        ["sh", "bash", "zsh"]
            .into_iter()
            .filter(|name| installed(name))
            .map(Some),
    );
    for program in programs {
        let mut arguments = json!({"connection": token});
        if let Some(program) = program {
            arguments["command"] = json!(program);
        }
        let opened = harness.ok("shell_open", arguments).await;
        assert!(opened.contains("managed mode"), "{program:?}: {opened}");
        let shell = shell_number(&opened);

        let text = harness
            .ok("shell_run", json!({"connection": token, "shell": shell, "command": "cd /tmp && export SSH_MCP_TEST=persisted"}))
            .await;
        assert!(text.contains("exited with code 0"), "{program:?}: {text}");
        let text = harness
            .ok("shell_run", json!({"connection": token, "shell": shell, "command": "pwd; echo \"$SSH_MCP_TEST\"; (exit 3)"}))
            .await;
        assert!(text.contains("exited with code 3"), "{program:?}: {text}");
        assert!(text.contains("/tmp\npersisted"), "{program:?}: {text}");
        assert!(
            !text.contains("SSH_MCP_TEST=persisted"),
            "input is not echoed: {text}"
        );

        let text = harness
            .ok("shell_run", json!({"connection": token, "shell": shell, "command": "git --version >/dev/null 2>&1; echo \"pager=$PAGER\""}))
            .await;
        assert!(text.contains("pager=cat"), "{program:?}: {text}");

        let long = format!("printf '%s' '{}' | wc -c", "a".repeat(6000));
        let text = harness
            .ok(
                "shell_run",
                json!({"connection": token, "shell": shell, "command": long}),
            )
            .await;
        assert!(
            text.contains("6000") && text.contains("exited with code 0"),
            "{program:?}: {text}"
        );

        let text = harness
            .ok(
                "shell_run",
                json!({"connection": token, "shell": shell, "command": "echo \"unclosed"}),
            )
            .await;
        assert!(text.contains("was incomplete"), "{program:?}: {text}");
        let text = harness
            .ok(
                "shell_run",
                json!({"connection": token, "shell": shell, "command": "echo recovered"}),
            )
            .await;
        assert!(
            text.contains("recovered") && text.contains("exited with code 0"),
            "{program:?}: {text}"
        );

        let text = harness
            .ok("shell_close", json!({"connection": token, "shell": shell}))
            .await;
        assert!(text.contains("closed"), "{text}");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn a_long_command_keeps_running_and_its_end_is_reported_once() {
    let (_server, harness, token) = terminal_connection().await;
    harness
        .ok("shell_open", json!({"connection": token, "command": "sh"}))
        .await;
    let text = harness
        .ok("shell_run", json!({"connection": token, "shell": 1, "command": "echo started; sleep 3; echo finished", "wait_seconds": 0.2}))
        .await;
    assert!(text.contains("is still running"), "{text}");
    if !text.contains("started") {
        let text = harness
            .ok(
                "shell_read",
                json!({"connection": token, "shell": 1, "until": "started", "wait_seconds": 10}),
            )
            .await;
        assert!(text.contains("started"), "{text}");
    }
    let refused = harness
        .error(
            "shell_run",
            json!({"connection": token, "shell": 1, "command": "echo second"}),
        )
        .await;
    assert!(refused.contains("still running"), "{refused}");

    let text = harness
        .ok(
            "shell_read",
            json!({"connection": token, "shell": 1, "wait_seconds": 10}),
        )
        .await;
    assert!(text.contains("exited with code 0"), "{text}");
    let output = text.split_once('\n').map_or("", |(_, output)| output);
    assert_eq!(output, "finished", "output is reported once: {text}");
    let text = harness
        .ok("shell_read", json!({"connection": token, "shell": 1}))
        .await;
    assert!(
        !text.contains("exited with code"),
        "the end is reported once: {text}"
    );
    assert!(text.contains("at the prompt"), "{text}");
}

#[cfg(unix)]
#[tokio::test]
async fn a_shell_that_exits_keeps_its_unread_output_readable() {
    let (_server, harness, token) = terminal_connection().await;
    harness
        .ok("shell_open", json!({"connection": token, "command": "sh"}))
        .await;
    harness
        .ok(
            "shell_send",
            json!({"connection": token, "shell": 1, "text": "abc"}),
        )
        .await;
    let refused = harness
        .error(
            "shell_run",
            json!({"connection": token, "shell": 1, "command": "true"}),
        )
        .await;
    assert!(refused.contains("partly typed line"), "{refused}");
    harness
        .ok(
            "shell_send",
            json!({"connection": token, "shell": 1, "keys": ["ctrl+u"]}),
        )
        .await;

    let text = harness
        .ok("shell_run", json!({"connection": token, "shell": 1, "command": "seq 1 20000; exit 0", "max_output_bytes": 1000}))
        .await;
    assert!(
        text.contains("read the rest of its output with shell_read"),
        "{text}"
    );
    let mut collected = text;
    for _ in 0..500 {
        let (is_error, text) = harness
            .call(
                "shell_read",
                json!({"connection": token, "shell": 1, "max_output_bytes": 100_000}),
            )
            .await;
        assert!(!is_error, "{text}");
        collected.push_str(&text);
        if text.contains("is gone") {
            break;
        }
    }
    assert!(collected.contains("\n20000"), "the last line was read");
    let refused = harness
        .error("shell_read", json!({"connection": token, "shell": 1}))
        .await;
    assert!(refused.contains("no shell 1"), "{refused}");
}

#[cfg(unix)]
#[tokio::test]
async fn prompts_are_answered_and_programs_interrupted_with_shell_send() {
    let (_server, harness, token) = terminal_connection().await;
    harness
        .ok("shell_open", json!({"connection": token, "command": "sh"}))
        .await;
    let text = harness
        .ok("shell_run", json!({"connection": token, "shell": 1, "command": "printf 'Name? '; read -r name; echo \"hello $name\"", "wait_seconds": 2}))
        .await;
    assert!(
        text.contains("possibly waiting for input: \"Name?\""),
        "{text}"
    );
    let text = harness
        .ok(
            "shell_send",
            json!({"connection": token, "shell": 1, "text": "agent\n"}),
        )
        .await;
    assert!(text.contains("hello agent"), "{text}");
    assert!(text.contains("exited with code 0"), "{text}");

    harness
        .ok(
            "shell_run",
            json!({"connection": token, "shell": 1, "command": "sleep 100", "wait_seconds": 0.2}),
        )
        .await;
    let text = harness
        .ok(
            "shell_send",
            json!({"connection": token, "shell": 1, "keys": ["ctrl+c"]}),
        )
        .await;
    assert!(text.contains("was interrupted"), "{text}");
    assert!(!text.ends_with('\n'), "no stray blank line: {text:?}");
    assert!(text.contains("at the prompt"), "{text}");

    let refused = harness
        .error(
            "shell_send",
            json!({"connection": token, "shell": 1, "keys": ["hyper"]}),
        )
        .await;
    assert!(refused.contains("Unknown key"), "{refused}");
}

#[cfg(unix)]
#[tokio::test]
async fn a_full_screen_program_is_shown_as_a_screen_and_raw_mode_is_plain() {
    let (_server, harness, token) = terminal_connection().await;
    harness
        .ok("shell_open", json!({"connection": token, "command": "sh"}))
        .await;
    harness
        .ok("shell_send", json!({"connection": token, "shell": 1, "text": "printf '\\033[?1049h\\033[HFULL SCREEN'; sleep 30\n"}))
        .await;
    let text = harness
        .ok("shell_read", json!({"connection": token, "shell": 1}))
        .await;
    assert!(text.contains("--- screen"), "{text}");
    assert!(text.contains("FULL SCREEN"), "{text}");
    assert!(
        !text.contains("possibly waiting"),
        "screen content is not a question: {text}"
    );

    let opened = harness
        .ok(
            "shell_open",
            json!({"connection": token, "command": "sh", "raw": true}),
        )
        .await;
    assert!(opened.contains("raw mode"), "{opened}");
    let refused = harness
        .error(
            "shell_run",
            json!({"connection": token, "shell": 2, "command": "echo x"}),
        )
        .await;
    assert!(refused.contains("raw mode"), "{refused}");
    let text = harness
        .ok("shell_send", json!({"connection": token, "shell": 2, "text": "echo raw-$((1+1))\n", "until": "raw-2"}))
        .await;
    assert!(text.contains("raw-2"), "{text}");
}

#[tokio::test]
async fn remote_text_files_are_read_written_and_edited_in_place() {
    let Some((sshd, harness, token)) = sshd_connection().await else {
        return;
    };
    let path = sshd.directory.path().join("notes.txt");
    let remote = path.display().to_string();
    let text = harness
        .ok(
            "write_file",
            json!({"connection": token, "path": remote, "content": "one\ntwo\nthree\ntwo\n"}),
        )
        .await;
    assert!(text.starts_with("Created"), "{text}");
    let text = harness
        .ok(
            "read_file",
            json!({"connection": token, "path": remote, "offset": 2, "limit": 2}),
        )
        .await;
    assert_eq!(
        text,
        "[lines 2-3 of 4; continue with offset 4]\ntwo\nthree\n"
    );

    let refused = harness
        .error(
            "edit_file",
            json!({"connection": token, "path": remote, "old_string": "two", "new_string": "2"}),
        )
        .await;
    assert!(refused.contains("matches 2 places"), "{refused}");
    harness
        .ok("edit_file", json!({"connection": token, "path": remote, "old_string": "two", "new_string": "2", "replace_all": true}))
        .await;
    harness
        .ok(
            "edit_file",
            json!({"connection": token, "path": remote, "old_string": "three", "new_string": "3"}),
        )
        .await;
    assert_eq!(
        std::fs::read_to_string(&path).expect("file"),
        "one\n2\n3\n2\n"
    );

    #[cfg(unix)]
    {
        let link = sshd.directory.path().join("link.txt");
        std::os::unix::fs::symlink(&path, &link).expect("symlink");
        harness
            .ok("write_file", json!({"connection": token, "path": link.display().to_string(), "content": "through the link\n"}))
            .await;
        assert!(
            std::fs::symlink_metadata(&link)
                .expect("link")
                .file_type()
                .is_symlink(),
            "the link survives"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("file"),
            "through the link\n"
        );
    }

    std::fs::write(sshd.directory.path().join("binary"), [0u8, 1, 2]).expect("binary");
    let refused = harness
        .error("read_file", json!({"connection": token, "path": sshd.directory.path().join("binary").display().to_string()}))
        .await;
    assert!(refused.contains("binary"), "{refused}");
}

#[tokio::test]
async fn folders_upload_and_download_with_symlinks_and_permissions() {
    let Some((sshd, harness, token)) = sshd_connection().await else {
        return;
    };
    let local = tempfile::tempdir().expect("local folder");
    let source = local.path().join("source");
    std::fs::create_dir_all(source.join("nested")).expect("folders");
    std::fs::write(source.join("nested/data.bin"), vec![
        7u8;
        3 * 1024 * 1024 + 5
    ])
    .expect("data");
    std::fs::write(source.join("run.sh"), "#!/bin/sh\necho hi\n").expect("script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            source.join("run.sh"),
            std::fs::Permissions::from_mode(0o750),
        )
        .expect("mode");
        std::os::unix::fs::symlink("run.sh", source.join("alias")).expect("symlink");
    }

    let remote = sshd.directory.path().join("uploaded");
    let text = harness
        .ok("upload", json!({"connection": token, "local_path": source.display().to_string(), "remote_path": remote.display().to_string()}))
        .await;
    assert!(text.starts_with("Uploaded 2 files"), "{text}");
    assert_eq!(
        std::fs::read(remote.join("nested/data.bin"))
            .expect("uploaded data")
            .len(),
        3 * 1024 * 1024 + 5
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(remote.join("run.sh"))
            .expect("script")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o750);
        assert_eq!(
            std::fs::read_link(remote.join("alias")).expect("link"),
            std::path::Path::new("run.sh")
        );
    }
    let refused = harness
        .error("upload", json!({"connection": token, "local_path": source.display().to_string(), "remote_path": remote.display().to_string()}))
        .await;
    assert!(refused.contains("already exists"), "{refused}");

    let back = local.path().join("back");
    let text = harness
        .ok("download", json!({"connection": token, "remote_path": remote.display().to_string(), "local_path": back.display().to_string()}))
        .await;
    assert!(text.starts_with("Downloaded 2 files"), "{text}");
    assert_eq!(
        std::fs::read(back.join("nested/data.bin")).expect("downloaded"),
        std::fs::read(source.join("nested/data.bin")).expect("source")
    );
    #[cfg(unix)]
    assert_eq!(
        std::fs::read_link(back.join("alias")).expect("link"),
        std::path::Path::new("run.sh")
    );
    let leftovers: Vec<_> = std::fs::read_dir(&back)
        .expect("listing")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains(".partial"))
        .collect();
    assert!(leftovers.is_empty(), "no partial files remain");

    let file = local.path().join("single.txt");
    std::fs::write(&file, "single").expect("file");
    let remote_file = sshd.directory.path().join("single.txt");
    harness
        .ok("upload", json!({"connection": token, "local_path": file.display().to_string(), "remote_path": remote_file.display().to_string(), "mode": "0600"}))
        .await;
    std::fs::write(&file, "replaced").expect("file");
    harness
        .ok("upload", json!({"connection": token, "local_path": file.display().to_string(), "remote_path": remote_file.display().to_string(), "overwrite": true}))
        .await;
    assert_eq!(
        std::fs::read_to_string(&remote_file).expect("file"),
        "replaced"
    );

    let refused = harness
        .error("download", json!({"connection": token, "remote_path": remote_file.display().to_string(), "local_path": "relative/path"}))
        .await;
    assert!(refused.contains("must be an absolute path"), "{refused}");
}

#[tokio::test]
async fn exec_against_openssh_stops_a_command_at_its_timeout() {
    let Some((_sshd, harness, token)) = sshd_connection().await else {
        return;
    };
    let text = harness
        .ok(
            "exec",
            json!({"connection": token, "command": "echo out; echo err >&2; exit 4"}),
        )
        .await;
    assert!(text.starts_with("[exit code 4"), "{text}");
    assert!(
        text.contains("--- stdout ---\nout\n--- stderr ---\nerr"),
        "{text}"
    );
    let text = harness
        .ok(
            "exec",
            json!({"connection": token, "command": "sleep 100", "timeout_seconds": 0.5}),
        )
        .await;
    assert!(text.contains("timed out after 0.5s"), "{text}");
    assert!(text.contains("killed by signal TERM"), "{text}");
}

#[tokio::test]
async fn a_password_accepted_with_more_required_continues_with_the_key() {
    let key = random_private_key();
    let harness = Harness::start(ALL_FEATURES).await;
    let server = TestServer::start(Logins {
        password: Some("hunter2".to_owned()),
        public_key: Some(key.public_key().clone()),
        password_then_key: true,
        ..Logins::default()
    })
    .await;
    let key_text = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .expect("key")
        .to_string();
    let text = harness
        .ok("connect", json!({"host": "127.0.0.1", "port": server.port, "user": "agent", "private_key": key_text, "password": "hunter2", "host_key_fingerprint": fingerprint(&server)}))
        .await;
    assert!(
        text.contains("Logged in with: password + publickey"),
        "{text}"
    );
}

/// The number of the shell a `shell_open` result names.
#[cfg(unix)]
fn shell_number(opened: &str) -> u32 {
    opened
        .split("[shell ")
        .nth(1)
        .and_then(|rest| rest.split(':').next())
        .and_then(|number| number.parse().ok())
        .expect("shell number")
}

#[cfg(unix)]
#[tokio::test]
async fn a_finished_command_nobody_read_is_still_reported_after_the_next_one() {
    let (_server, harness, token) = terminal_connection().await;
    let shell = shell_number(
        &harness
            .ok("shell_open", json!({"connection": token, "command": "sh"}))
            .await,
    );
    let text = harness
        .ok("shell_run", json!({"connection": token, "shell": shell, "command": "sleep 1; (exit 2)", "wait_seconds": 0}))
        .await;
    assert!(text.contains("is still running"), "{text}");
    // Wait for it to finish without reading it: the status does not consume anything.
    for _ in 0..100 {
        let status = harness
            .ok("connection_status", json!({"connection": token}))
            .await;
        if status.contains("at the prompt") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let text = harness
        .ok(
            "shell_run",
            json!({"connection": token, "shell": shell, "command": "echo next"}),
        )
        .await;
    assert!(
        text.contains("`sleep 1; (exit 2)` exited with code 2"),
        "{text}"
    );
    assert!(text.contains("`echo next` exited with code 0"), "{text}");
}

#[cfg(unix)]
#[tokio::test]
async fn an_incomplete_command_is_canceled_when_shell_read_finds_it() {
    let (_server, harness, token) = terminal_connection().await;
    let shell = shell_number(
        &harness
            .ok("shell_open", json!({"connection": token, "command": "sh"}))
            .await,
    );
    let mut seen = harness
        .ok("shell_run", json!({"connection": token, "shell": shell, "command": "echo \"unclosed", "wait_seconds": 0}))
        .await;
    seen.push_str(
        &harness
            .ok(
                "shell_read",
                json!({"connection": token, "shell": shell, "wait_seconds": 10}),
            )
            .await,
    );
    assert!(seen.contains("was incomplete"), "{seen}");
    let text = harness
        .ok(
            "shell_run",
            json!({"connection": token, "shell": shell, "command": "echo recovered"}),
        )
        .await;
    assert!(
        text.contains("recovered") && text.contains("exited with code 0"),
        "{text}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_canceled_call_interrupts_nothing_and_consumes_nothing() {
    let (_server, harness, token) = terminal_connection().await;
    let shell = shell_number(
        &harness
            .ok("shell_open", json!({"connection": token, "command": "sh"}))
            .await,
    );
    let Value::Object(arguments) = json!({"connection": token, "shell": shell, "command": "echo before; sleep 1; echo after", "wait_seconds": 30})
    else {
        unreachable!();
    };
    // Dropping the call sends the server a cancellation, as a client does at its deadline.
    let call = harness.client.call_tool_once(
        CallToolRequestParams::new("shell_run".to_owned()).with_arguments(arguments),
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(500), call)
            .await
            .is_err(),
        "the call returned before it was canceled"
    );
    let text = harness
        .ok(
            "shell_read",
            json!({"connection": token, "shell": shell, "wait_seconds": 10}),
        )
        .await;
    assert!(text.contains("before\nafter"), "{text}");
    assert!(text.contains("exited with code 0"), "{text}");
}

#[cfg(unix)]
#[tokio::test]
async fn special_files_are_skipped_and_read_only_folders_copy_both_ways() {
    use std::os::unix::fs::PermissionsExt;
    let Some((sshd, harness, token)) = sshd_connection().await else {
        return;
    };
    let remote = sshd.directory.path().join("tree");
    std::fs::create_dir_all(remote.join("locked")).expect("folders");
    std::fs::write(remote.join("locked/inside.txt"), "kept").expect("file");
    let _socket =
        std::os::unix::net::UnixListener::bind(remote.join("agent.sock")).expect("socket");
    let read_only = std::fs::Permissions::from_mode(0o555);
    std::fs::set_permissions(remote.join("locked"), read_only.clone()).expect("mode");

    let local = tempfile::tempdir().expect("local folder");
    let back = local.path().join("tree");
    let text = harness
        .ok("download", json!({"connection": token, "remote_path": remote.display().to_string(), "local_path": back.display().to_string()}))
        .await;
    assert!(text.contains("1 special file"), "{text}");
    assert_eq!(
        std::fs::read_to_string(back.join("locked/inside.txt")).expect("file"),
        "kept"
    );
    let mode = std::fs::metadata(back.join("locked"))
        .expect("folder")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o555);

    let uploaded = sshd.directory.path().join("uploaded");
    let text = harness
        .ok("upload", json!({"connection": token, "local_path": back.display().to_string(), "remote_path": uploaded.display().to_string()}))
        .await;
    assert!(text.starts_with("Uploaded 1 file"), "{text}");
    assert_eq!(
        std::fs::read_to_string(uploaded.join("locked/inside.txt")).expect("file"),
        "kept"
    );
    let writable = std::fs::Permissions::from_mode(0o755);
    for folder in [
        remote.join("locked"),
        back.join("locked"),
        uploaded.join("locked"),
    ] {
        std::fs::set_permissions(folder, writable.clone()).expect("mode");
    }
}

#[tokio::test]
async fn exec_returns_when_the_command_exits_though_a_background_process_holds_its_output() {
    let Some((_sshd, harness, token)) = sshd_connection().await else {
        return;
    };
    let started = std::time::Instant::now();
    let text = harness
        .ok(
            "exec",
            json!({"connection": token, "command": "echo hi; sleep 30 &", "timeout_seconds": 20}),
        )
        .await;
    assert!(started.elapsed() < Duration::from_secs(10), "{text}");
    assert!(text.starts_with("[exit code 0 after"), "{text}");
    assert!(text.contains("holds its output open"), "{text}");
    assert!(text.ends_with("--- stdout ---\nhi"), "{text}");
}
