//! `server` — runs on the **remote** Windows machine you want to control.
//!
//! Listens on a public-key-addressable QUIC endpoint. When the `client`
//! opens a bi-directional stream, this binary dials the local RDP service
//! on `127.0.0.1:3389` and bridges bytes both ways. The connection is QUIC,
//! end-to-end encrypted — RDP does not need TLS itself.
//!
//! Usage:
//!     cargo run --release --bin server
//!
//! On startup it prints the endpoint's public key. Copy that string to the
//! `client` running on the controlling machine.

use anyhow::Result;
use iroh::{
    Endpoint, EndpointId, RelayMode,
    endpoint::{Connection, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use iroh_rdp_tunnel::ALPN;
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let secret_key = iroh::SecretKey::generate();
    let endpoint_id: EndpointId = secret_key.public();

    // Use n0's discovery (DNS pkarr + public relay). Set NO_RELAY=1 to
    // disable the relay — only useful when both peers are on the same LAN
    // and you also pass direct IP addresses.
    let relay_mode = if std::env::var_os("NO_RELAY").is_some() {
        RelayMode::Disabled
    } else {
        RelayMode::Default
    };

    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .relay_mode(relay_mode)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;

    let router = Router::builder(endpoint.clone())
        .accept(ALPN.to_vec(), BridgeHandler)
        .spawn();

    // Wait until the endpoint is online (DNS announcements finished,
    // relay reachable).
    endpoint.online().await;

    println!();
    println!("=========================================================");
    println!(" iroh-rdp-tunnel SERVER is ready");
    println!("=========================================================");
    println!(" Copy this endpoint id into the `client` on the other machine:");
    println!();
    println!("     {}", endpoint_id);
    println!();
    println!(" (Tip: the server's local RDP must be enabled at 127.0.0.1:3389)");
    println!(" Waiting for client connection... (Ctrl-C to exit)");
    println!();

    // Block until Ctrl-C, then shut down cleanly.
    println!("(press Ctrl-C to stop the server)");
    tokio::signal::ctrl_c().await?;
    println!("\nshutting down...");
    router.shutdown().await?;
    Ok(())
}

/// Protocol handler that forwards each incoming RDP stream to local 3389.
#[derive(Debug, Clone, Copy)]
struct BridgeHandler;

impl ProtocolHandler for BridgeHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let remote = conn.remote_id();
        tracing::info!("incoming connection from {remote}");

        loop {
            let (send, recv) = match conn.accept_bi().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::info!("accept loop stopped for {remote}: {e}");
                    return Ok(());
                }
            };

            let tcp = match TcpStream::connect("127.0.0.1:3389").await {
                Ok(t) => t,
                Err(e) => {
                    let msg = format!("local RDP not running on 127.0.0.1:3389: {e}");
                    tracing::warn!("{msg}");
                    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, msg);
                    return Err(AcceptError::from(io_err));
                }
            };

            tokio::spawn(bridge(send, recv, tcp));
        }
    }
}

/// Forward bytes between an iroh bi-di stream and a local TCP socket.
async fn bridge(send: iroh::endpoint::SendStream, recv: iroh::endpoint::RecvStream, tcp: TcpStream) {
    let (mut qr, mut qs) = (recv, send);
    let mut tcp = tcp;
    let (mut tcp_r, mut tcp_w) = tcp.split();

    let q2t = tokio::io::copy(&mut qr, &mut tcp_w);
    let t2q = tokio::io::copy(&mut tcp_r, &mut qs);
    let _ = tokio::join!(q2t, t2q);

    // Best-effort graceful shutdown in both directions.
    let _ = qs.finish();
    let _ = tcp_w.shutdown().await;
}
