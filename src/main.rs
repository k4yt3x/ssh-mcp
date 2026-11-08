//! ssh-mcp: an MCP server over stdio that gives an agent persistent SSH connections, shells, file
//! transfer and port forwarding.

// A test panics on failure by design, so the `[lints.clippy]` panic lints in `Cargo.toml` are
// relaxed for test builds alone.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::indexing_slicing,
        clippy::redundant_clone,
        clippy::unused_async
    )
)]

mod client;
mod connection;
mod exec;
mod forward;
mod host_key;
mod output;
mod paths;
mod server;
mod sftp;
mod shell;
#[cfg(test)]
mod testing;

use clap::Parser;
use rmcp::ServiceExt;
use tracing_subscriber::{
    EnvFilter, Layer,
    filter::{LevelFilter, Targets},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

use crate::server::{Features, SshServer};

/// An MCP server for SSH, speaking MCP over stdin and stdout.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Arguments {
    /// Remove the SFTP tools: read_file, write_file, edit_file, upload and download. Without them
    /// the server writes no local files and reads none except key, certificate and known_hosts
    /// files.
    #[arg(long)]
    disable_sftp: bool,
    /// Offer forward_local: a port on 127.0.0.1 here that reaches a host from the server.
    #[arg(long)]
    enable_local_forwarding: bool,
    /// Offer forward_remote: a port on the server that reaches a host from this machine.
    #[arg(long)]
    enable_remote_forwarding: bool,
    /// Offer forward_dynamic: a SOCKS5 proxy on 127.0.0.1 here whose connections leave from the
    /// server.
    #[arg(long)]
    enable_dynamic_forwarding: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    // rmcp logs every request and result at debug, tool arguments included, and those carry
    // passwords and keys. Its target stays at info whatever RUST_LOG asks for.
    let never_log_requests = Targets::new()
        .with_target("rmcp", LevelFilter::INFO)
        .with_default(LevelFilter::TRACE);
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_ansi(false)
                .with_filter(EnvFilter::from_default_env())
                .with_filter(never_log_requests),
        )
        .init();
    let server = SshServer::new(Features {
        sftp: !arguments.disable_sftp,
        local_forwarding: arguments.enable_local_forwarding,
        remote_forwarding: arguments.enable_remote_forwarding,
        dynamic_forwarding: arguments.enable_dynamic_forwarding,
    });
    let service = server.serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
