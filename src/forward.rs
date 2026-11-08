//! Port forwarding through an open connection: local (a port here reaches a host the server can
//! reach), remote (a port on the server reaches a host this machine can reach) and dynamic (a
//! SOCKS5 proxy here whose connections leave from the server). Local listeners bind 127.0.0.1
//! only.

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{
    client::{RemoteForwardTarget, RemoteForwardTargets, SshHandle},
    output::{ToolError, lock},
};

/// How long a SOCKS client has to finish its handshake.
const SOCKS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a listener waits after a failed accept before the next. A failure such as running out
/// of file descriptors repeats at once, and retrying without a pause would spin a CPU.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// The forwards of one connection.
#[derive(Default)]
pub(crate) struct ForwardTable {
    last_number: u32,
    forwards: BTreeMap<u32, Forward>,
}

impl ForwardTable {
    /// One line per forward, for the connection status.
    pub(crate) fn describe(&self) -> Vec<String> {
        self.forwards
            .iter()
            .map(|(number, forward)| format!("forward {number}: {}", forward.description))
            .collect()
    }

    fn insert(&mut self, forward: Forward) -> u32 {
        self.last_number += 1;
        self.forwards.insert(self.last_number, forward);
        self.last_number
    }
}

/// One forward.
struct Forward {
    description: String,
    stop: CancellationToken,
    /// The task accepting connections on a local listener, which ends soon after `stop`.
    listener: Option<JoinHandle<()>>,
    /// The server-side listener of a remote forward: its bind address and port.
    remote_listener: Option<(String, u32)>,
}

async fn bind_loopback(port: u16) -> Result<(TcpListener, u16), ToolError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .map_err(|error| {
            ToolError::new(format!(
                "Port {port} on 127.0.0.1 could not be opened: {error}"
            ))
        })?;
    let port = listener
        .local_addr()
        .map_err(|error| ToolError::new(format!("The listening port is unknown: {error}")))?
        .port();
    Ok((listener, port))
}

/// Accept connections on `listener` until `stop` fires, handing each to `serve`.
fn spawn_accept_loop<F, Fut>(
    listener: TcpListener,
    port: u16,
    stop: CancellationToken,
    serve: F,
) -> JoinHandle<()>
where
    F: Fn(TcpStream, SocketAddr) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((socket, peer)) => {
                        tokio::spawn(serve(socket, peer));
                    }
                    Err(error) => {
                        tracing::debug!("accepting on 127.0.0.1:{port} failed: {error}");
                        tokio::select! {
                            () = tokio::time::sleep(ACCEPT_RETRY_DELAY) => {}
                            () = stop.cancelled() => break,
                        }
                    }
                },
                () = stop.cancelled() => break,
            }
        }
    })
}

/// Carry one accepted connection through a `direct-tcpip` channel to `host:port`.
async fn carry_through_server(
    handle: &SshHandle,
    mut socket: TcpStream,
    peer: SocketAddr,
    host: &str,
    port: u16,
) {
    match handle
        .channel_open_direct_tcpip(
            host,
            u32::from(port),
            peer.ip().to_string(),
            u32::from(peer.port()),
        )
        .await
    {
        Ok(channel) => {
            let mut stream = channel.into_stream();
            if let Err(error) = tokio::io::copy_bidirectional(&mut socket, &mut stream).await {
                tracing::debug!("forwarded connection to {host}:{port} ended: {error}");
            }
        }
        Err(error) => tracing::debug!("the server could not reach {host}:{port}: {error}"),
    }
}

/// Start a local forward: connections to `local_port` on 127.0.0.1 reach `remote_host:remote_port`
/// from the server.
pub(crate) async fn open_local(
    handle: Arc<SshHandle>,
    table: &Mutex<ForwardTable>,
    connection_closed: &CancellationToken,
    remote_host: String,
    remote_port: u16,
    local_port: u16,
) -> Result<String, ToolError> {
    let (listener, port) = bind_loopback(local_port).await?;
    let stop = connection_closed.child_token();
    let task = spawn_accept_loop(listener, port, stop.clone(), {
        let remote_host = remote_host.clone();
        move |socket, peer| {
            let handle = Arc::clone(&handle);
            let remote_host = remote_host.clone();
            async move {
                carry_through_server(&handle, socket, peer, &remote_host, remote_port).await;
            }
        }
    });
    let description = format!("local 127.0.0.1:{port} to {remote_host}:{remote_port}");
    let number = lock(table).insert(Forward {
        description,
        stop,
        listener: Some(task),
        remote_listener: None,
    });
    Ok(format!(
        "Forward {number}: 127.0.0.1:{port} on this machine now reaches {remote_host}:{remote_port} through the server."
    ))
}

/// Start a remote forward: connections to `remote_port` on the server reach
/// `local_host:local_port` from this machine.
pub(crate) async fn open_remote(
    handle: &SshHandle,
    table: &Mutex<ForwardTable>,
    targets: &RemoteForwardTargets,
    remote_bind_address: String,
    remote_port: u16,
    local_host: String,
    local_port: u16,
) -> Result<String, ToolError> {
    let granted = handle
        .tcpip_forward(remote_bind_address.clone(), u32::from(remote_port))
        .await
        .map_err(|error| {
            ToolError::new(format!(
                "The server refused to listen on {remote_bind_address}:{remote_port}: {error}"
            ))
        })?;
    let port = if remote_port == 0 {
        granted
    } else {
        u32::from(remote_port)
    };
    // The server names only the port when it forwards a connection, so two forwards on one port
    // (on different addresses) could not be told apart.
    let taken = {
        let mut targets = lock(targets);
        let taken = targets.contains_key(&port);
        if !taken {
            targets.insert(port, RemoteForwardTarget {
                host: local_host.clone(),
                port: local_port,
            });
        }
        taken
    };
    if taken {
        if let Err(error) = handle
            .cancel_tcpip_forward(remote_bind_address.clone(), port)
            .await
        {
            tracing::debug!("the refused remote forward could not be canceled: {error}");
        }
        return Err(ToolError::new(format!(
            "Another forward of this connection already uses port {port} on the server; close it first or use another port."
        )));
    }
    let description =
        format!("remote {remote_bind_address}:{port} on the server to {local_host}:{local_port}");
    let number = lock(table).insert(Forward {
        description,
        stop: CancellationToken::new(),
        listener: None,
        remote_listener: Some((remote_bind_address.clone(), port)),
    });
    Ok(format!(
        "Forward {number}: port {port} on the server ({remote_bind_address}) now reaches {local_host}:{local_port} from this machine."
    ))
}

/// Start a dynamic forward: a SOCKS5 proxy on 127.0.0.1 whose connections are made from the
/// server.
pub(crate) async fn open_dynamic(
    handle: Arc<SshHandle>,
    table: &Mutex<ForwardTable>,
    connection_closed: &CancellationToken,
    local_port: u16,
) -> Result<String, ToolError> {
    let (listener, port) = bind_loopback(local_port).await?;
    let stop = connection_closed.child_token();
    let task = spawn_accept_loop(listener, port, stop.clone(), move |socket, peer| {
        let handle = Arc::clone(&handle);
        async move {
            serve_socks_client(&handle, socket, peer).await;
        }
    });
    let number = lock(table).insert(Forward {
        description: format!("dynamic SOCKS5 proxy on 127.0.0.1:{port}"),
        stop,
        listener: Some(task),
        remote_listener: None,
    });
    Ok(format!(
        "Forward {number}: a SOCKS5 proxy listens on 127.0.0.1:{port}; its connections are made from the server."
    ))
}

/// Stop forward `number`.
pub(crate) async fn close(
    handle: &SshHandle,
    table: &Mutex<ForwardTable>,
    targets: &RemoteForwardTargets,
    number: u32,
) -> Result<String, ToolError> {
    let forward = lock(table).forwards.remove(&number).ok_or_else(|| {
        ToolError::new(format!(
            "This connection has no forward {number}. Use connection_status to see its forwards."
        ))
    })?;
    forward.stop.cancel();
    // The listening port is closed once the accept task has ended.
    if let Some(task) = forward.listener
        && let Err(error) = task.await
    {
        tracing::debug!("the listener of forward {number} ended abnormally: {error}");
    }
    if let Some((address, port)) = &forward.remote_listener {
        lock(targets).remove(port);
        if let Err(error) = handle.cancel_tcpip_forward(address.clone(), *port).await {
            return Ok(format!(
                "Forward {number} stopped here, but the server did not confirm it stopped listening: {error}"
            ));
        }
    }
    Ok(format!(
        "Forward {number} ({}) stopped.",
        forward.description
    ))
}

/// SOCKS5 reply codes (RFC 1928 section 6).
const SOCKS_SUCCEEDED: u8 = 0x00;
const SOCKS_GENERAL_FAILURE: u8 = 0x01;
const SOCKS_CONNECTION_REFUSED: u8 = 0x05;
const SOCKS_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const SOCKS_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// The target a SOCKS client asked to reach, or the reply code refusing it.
async fn socks_handshake(socket: &mut TcpStream) -> Result<(String, u16), Option<u8>> {
    let mut greeting = [0u8; 2];
    socket.read_exact(&mut greeting).await.map_err(|_| None)?;
    let [version, method_count] = greeting;
    if version != 5 {
        return Err(None);
    }
    let mut methods = vec![0u8; usize::from(method_count)];
    socket.read_exact(&mut methods).await.map_err(|_| None)?;
    if !methods.contains(&0) {
        // 0xFF: no acceptable method; only "no authentication" is offered on a loopback port.
        socket.write_all(&[5, 0xff]).await.map_err(|_| None)?;
        return Err(None);
    }
    socket.write_all(&[5, 0]).await.map_err(|_| None)?;
    let mut request = [0u8; 4];
    socket.read_exact(&mut request).await.map_err(|_| None)?;
    let [version, command, _, address_type] = request;
    if version != 5 {
        return Err(None);
    }
    let host = match address_type {
        1 => {
            let mut octets = [0u8; 4];
            socket.read_exact(&mut octets).await.map_err(|_| None)?;
            Ipv4Addr::from(octets).to_string()
        }
        3 => {
            let mut length = [0u8; 1];
            socket.read_exact(&mut length).await.map_err(|_| None)?;
            let mut name = vec![0u8; usize::from(length[0])];
            socket.read_exact(&mut name).await.map_err(|_| None)?;
            String::from_utf8(name).map_err(|_| Some(SOCKS_GENERAL_FAILURE))?
        }
        4 => {
            let mut octets = [0u8; 16];
            socket.read_exact(&mut octets).await.map_err(|_| None)?;
            Ipv6Addr::from(octets).to_string()
        }
        _ => return Err(Some(SOCKS_ADDRESS_TYPE_NOT_SUPPORTED)),
    };
    let mut port = [0u8; 2];
    socket.read_exact(&mut port).await.map_err(|_| None)?;
    if command != 1 {
        return Err(Some(SOCKS_COMMAND_NOT_SUPPORTED));
    }
    Ok((host, u16::from_be_bytes(port)))
}

async fn send_socks_reply(socket: &mut TcpStream, code: u8) -> std::io::Result<()> {
    socket.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

async fn serve_socks_client(handle: &SshHandle, mut socket: TcpStream, peer: SocketAddr) {
    let target =
        match tokio::time::timeout(SOCKS_HANDSHAKE_TIMEOUT, socks_handshake(&mut socket)).await {
            Ok(Ok(target)) => target,
            Ok(Err(Some(code))) => {
                if let Err(error) = send_socks_reply(&mut socket, code).await {
                    tracing::debug!("a SOCKS refusal could not be sent: {error}");
                }
                return;
            }
            Ok(Err(None)) | Err(_) => return,
        };
    let (host, port) = target;
    let channel = match handle
        .channel_open_direct_tcpip(
            host.as_str(),
            u32::from(port),
            peer.ip().to_string(),
            u32::from(peer.port()),
        )
        .await
    {
        Ok(channel) => channel,
        Err(error) => {
            tracing::debug!("the server could not reach {host}:{port}: {error}");
            let code = match error {
                russh::Error::ChannelOpenFailure(_) => SOCKS_CONNECTION_REFUSED,
                _ => SOCKS_GENERAL_FAILURE,
            };
            if let Err(error) = send_socks_reply(&mut socket, code).await {
                tracing::debug!("a SOCKS refusal could not be sent: {error}");
            }
            return;
        }
    };
    if let Err(error) = send_socks_reply(&mut socket, SOCKS_SUCCEEDED).await {
        tracing::debug!("the SOCKS reply could not be sent: {error}");
        return;
    }
    let mut stream = channel.into_stream();
    if let Err(error) = tokio::io::copy_bidirectional(&mut socket, &mut stream).await {
        tracing::debug!("proxied connection to {host}:{port} ended: {error}");
    }
}
