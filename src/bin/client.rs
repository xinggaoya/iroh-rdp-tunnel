//! `client` — runs on the machine that wants to **remotely control** a
//! Windows desktop. Listens on `127.0.0.1:13389` (a fake "local RDP") and
//! forwards each incoming TCP connection to the remote `server` over QUIC.
//!
//! Usage:
//!     cargo run --release --bin client -- <endpoint_id>
//!
//! Then open Windows' built-in Remote Desktop Connection (mstsc) and connect
//! to `127.0.0.1:13389`. Any RDP client works: mstsc on Windows, the macOS
//! app, the mobile `RD Client`, etc.

use anyhow::{Context, Result};
use clap::Parser;
use iroh::{Endpoint, EndpointAddr, EndpointId, endpoint::presets};
use iroh_rdp_tunnel::ALPN;
use tokio::net::{TcpListener, TcpStream};

const LISTEN_ADDR: &str = "127.0.0.1:13389";

#[derive(Parser, Debug)]
#[command(name = "iroh-rdp-tunnel client", version)]
struct Args {
    /// The endpoint id (public key) printed by the `server`.
    #[arg(value_name = "ENDPOINT_ID")]
    remote: String,

    /// Override the local listening address (default `127.0.0.1:13389`).
    #[arg(long, default_value = LISTEN_ADDR)]
    listen: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let remote_id: EndpointId = args
        .remote
        .trim()
        .parse()
        .with_context(|| format!("not a valid endpoint id `{}`", args.remote))?;
    // Resolve via the default n0 DNS / discovery; iroh will look up the
    // current relay + direct addresses for this id.
    let remote_addr = EndpointAddr::from(remote_id);

    // Shared endpoint so multiple mstsc connections reuse the same handshake.
    let endpoint = Endpoint::builder(presets::N0).bind().await?;

    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("could not bind local TCP {}", args.listen))?;

    println!();
    println!("=========================================================");
    println!(" iroh-rdp-tunnel CLIENT is ready");
    println!("=========================================================");
    println!(" remote endpoint   = {remote_id}");
    println!(" local TCP listen  = {}", args.listen);
    println!();
    println!(" Open Windows' Remote Desktop Connection (mstsc) and connect to:");
    println!("     {}", args.listen);
    println!(" (Ctrl-C to exit)");

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("local TCP accept error: {e}");
                continue;
            }
        };
        tracing::info!("local RDP client connected from {peer}");

        let endpoint = endpoint.clone();
        let remote_addr = remote_addr.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_session(endpoint, remote_addr, tcp).await {
                tracing::warn!("session ended with error: {e:#}");
            }
        });
    }
}

/// Bridge one TCP connection from `mstsc` to the remote endpoint over QUIC.
async fn handle_session(endpoint: Endpoint, remote_addr: EndpointAddr, mut local: TcpStream) -> Result<()> {
    let conn = endpoint.connect(remote_addr, ALPN).await?;
    let (mut send, mut recv) = conn.open_bi().await?;

    let (mut local_r, mut local_w) = local.split();
    let l_to_q = tokio::io::copy(&mut local_r, &mut send);
    let q_to_l = tokio::io::copy(&mut recv, &mut local_w);
    let (a, b) = tokio::join!(l_to_q, q_to_l);
    a?;
    b?;
    let _ = send.finish();

    let _ = conn.close(0u32.into(), b"bye");
    Ok(())
}
