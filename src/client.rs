//! The russh client handler: host key verification during key exchange, the login banner, the
//! server's version string, and the server-initiated channels this client accepts.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use russh::{
    Channel,
    client::{self, ChannelOpenHandle, Msg, Session},
    keys::{PublicKeyOrCertificate, ssh_key::PublicKey},
};
use tokio_util::sync::CancellationToken;

use crate::{
    host_key::{HostKeyPolicy, HostKeyReport, Verdict},
    output::{ToolError, format_duration, lock},
};

/// An authenticated or authenticating SSH session.
pub(crate) type SshHandle = client::Handle<ClientHandler>;

/// How long a request to the server may take: to be sent, and to be answered when it waits for an
/// answer. russh queues a request behind the connection's outgoing data and waits for answers
/// without limit, so a server or network that stops would otherwise hold a call forever.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long closing something may take before it is given up on. Closing is best effort, and the
/// idle cleanup closes connections one after another, so it must not wait long.
pub(crate) const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Await `request` for at most `limit`, describing a failure as being unable to `action`, such as
/// "start the shell".
pub(crate) async fn bounded<T>(
    limit: Duration,
    action: &str,
    request: impl Future<Output = Result<T, russh::Error>>,
) -> Result<T, ToolError> {
    match tokio::time::timeout(limit, request).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(ToolError::new(format!("Could not {action}: {error}"))),
        Err(_) => Err(ToolError::new(format!(
            "Could not {action}: the server did not respond within {}.",
            format_duration(limit)
        ))),
    }
}

/// Await `request`, whose failure needs only logging (closing something, say), for at most
/// `limit`. Returns whether it completed.
pub(crate) async fn best_effort(
    limit: Duration,
    action: &str,
    request: impl Future<Output = Result<(), russh::Error>>,
) -> bool {
    match tokio::time::timeout(limit, request).await {
        Ok(Ok(())) => true,
        Ok(Err(error)) => {
            tracing::debug!("{action} failed: {error}");
            false
        }
        Err(_) => {
            tracing::debug!("{action} got no response within {}", format_duration(limit));
            false
        }
    }
}

/// Open a session channel for a command, a shell or SFTP, giving up when the server does not
/// answer within [`REQUEST_TIMEOUT`] or `cancel` fires.
pub(crate) async fn open_session_channel(
    handle: &SshHandle,
    cancel: &CancellationToken,
) -> Result<Channel<Msg>, ToolError> {
    tokio::select! {
        opened = bounded(REQUEST_TIMEOUT, "open a channel", handle.channel_open_session()) => opened,
        () = cancel.cancelled() => Err(ToolError::new("The call was canceled before the server opened a channel.")),
    }
}

/// Where a remote forward delivers the connections the server forwards back to this client.
#[derive(Clone, Debug)]
pub(crate) struct RemoteForwardTarget {
    /// Host on this machine (or reachable from it) to connect to.
    pub(crate) host: String,
    /// Port on that host.
    pub(crate) port: u16,
}

/// The remote forwards of one connection, keyed by the port the server listens on.
pub(crate) type RemoteForwardTargets = Arc<Mutex<HashMap<u32, RemoteForwardTarget>>>;

/// What the handler learned during the handshake, read by the connect that started it.
#[derive(Default)]
pub(crate) struct HandshakeFacts {
    /// The host key the server presented and the verdict on it.
    pub(crate) host_key: Option<(HostKeyReport, Verdict)>,
    /// The banner the server sent before authentication.
    pub(crate) banner: Option<String>,
    /// The server's identification string, such as `SSH-2.0-OpenSSH_9.6`.
    pub(crate) server_version: Option<String>,
}

/// Handles the server's side of one connection.
pub(crate) struct ClientHandler {
    host: String,
    port: u16,
    policy: Arc<HostKeyPolicy>,
    facts: Arc<Mutex<HandshakeFacts>>,
    remote_forward_targets: RemoteForwardTargets,
}

impl ClientHandler {
    /// A handler for a connection to `host:port` that checks the host key with `policy` and
    /// records what it learns in `facts`.
    pub(crate) fn new(
        host: String,
        port: u16,
        policy: Arc<HostKeyPolicy>,
        facts: Arc<Mutex<HandshakeFacts>>,
        remote_forward_targets: RemoteForwardTargets,
    ) -> Self {
        Self {
            host,
            port,
            policy,
            facts,
            remote_forward_targets,
        }
    }

    fn record<F: FnOnce(&mut HandshakeFacts)>(&self, update: F) {
        update(&mut lock(&self.facts));
    }
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            PublicKeyOrCertificate::Certificate(certificate) => {
                PublicKey::from(certificate.public_key().clone())
            }
        };
        let report = HostKeyReport::new(&self.host, self.port, &key);
        let verdict = self.policy.verify(&self.host, self.port, &key);
        let accepted = matches!(verdict, Verdict::Accepted(_));
        self.record(|facts| facts.host_key = Some((report, verdict)));
        Ok(accepted)
    }

    async fn auth_banner(
        &mut self,
        banner: &str,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let banner = banner.trim_end().to_owned();
        self.record(|facts| facts.banner = Some(banner));
        Ok(())
    }

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        _names: &russh::Names,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let version = String::from_utf8_lossy(session.remote_sshid())
            .trim_end()
            .to_owned();
        self.record(|facts| {
            facts.server_version.get_or_insert(version);
        });
        Ok(())
    }

    // The server may only open channels this client asked for: forwarded connections for a
    // remote forward it requested. Dropping a `ChannelOpenHandle` rejects the channel.

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let target = lock(&self.remote_forward_targets)
            .get(&connected_port)
            .cloned();
        let Some(target) = target else {
            drop(reply);
            return Ok(());
        };
        reply.accept().await;
        tokio::spawn(async move {
            match tokio::net::TcpStream::connect((target.host.as_str(), target.port)).await {
                Ok(mut socket) => {
                    let mut stream = channel.into_stream();
                    if let Err(error) =
                        tokio::io::copy_bidirectional(&mut stream, &mut socket).await
                    {
                        tracing::debug!(
                            "remote forward to {}:{} ended: {error}",
                            target.host,
                            target.port
                        );
                    }
                }
                Err(error) => {
                    tracing::debug!(
                        "remote forward could not reach {}:{}: {error}",
                        target.host,
                        target.port
                    );
                    best_effort(
                        CLOSE_TIMEOUT,
                        "closing the forwarded channel",
                        channel.close(),
                    )
                    .await;
                }
            }
        });
        Ok(())
    }

    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        drop(reply);
        Ok(())
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        drop(reply);
        Ok(())
    }

    async fn server_channel_open_x11(
        &mut self,
        _channel: Channel<Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        drop(reply);
        Ok(())
    }

    async fn server_channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        drop(reply);
        Ok(())
    }

    async fn server_channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        drop(reply);
        Ok(())
    }

    async fn server_channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        drop(reply);
        Ok(())
    }
}
