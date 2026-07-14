//! `server` — runs on the **remote** Windows machine you want to control.
//!
//! Listens on a public-key-addressable QUIC endpoint. When the `client`
//! opens a bi-directional stream, this binary dials the local RDP service
//! on `127.0.0.1:3389` and bridges bytes both ways. The connection is QUIC,
//! end-to-end encrypted — RDP does not need TLS itself.
//!
//! Address-publishing trick:
//!     The default N0 preset only publishes relay URLs via pkarr (to keep
//!     public IPs private by default). We add a *second* PkarrPublisher with
//!     `AddrFilter::unfiltered()` so that the server's public IPv6 / IPv4
//!     addresses get advertised too — letting the client attempt a direct
//!     connection and skip the relay.
//!
//! Usage:
//!     cargo run --release --bin server
//!
//! On startup it prints the endpoint's public key. Copy that string to the
//! `client` running on the controlling machine.

use anyhow::Result;
use iroh::{
    Endpoint, EndpointId, RelayMode, TransportAddr,
    address_lookup::{AddrFilter, PkarrPublisher},
    endpoint::{Connection, PortmapperConfig, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use iroh_rdp_tunnel::{ALPN, BUILD_TAG};
use tokio::{io::AsyncWriteExt, net::TcpStream};

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
    // disable the relay entirely; only do this when both peers are on the
    // same LAN and can reach each other's direct addresses.
    let relay_mode = if std::env::var_os("NO_RELAY").is_some() {
        RelayMode::Disabled
    } else {
        RelayMode::Default
    };

    // OPTIONAL: filtering modes — useful when (e.g.) the server has no IPv6
    // at all and iroh keeps trying IPv6 paths that fail with WSAENETUNREACH.
    //   FORCE_IPV6        — publish ONLY public IPv6
    //   FORCE_IPV4_ONLY   — publish ONLY public IPv4
    //   (default, unset)  — publish everything via AddrFilter::unfiltered()
    //
    // FORCE_IPV4_ONLY is the right choice when the server side has no IPv6
    // routing but does have a working UPnP-mapped public IPv4 — it forces
    // the client to skip IPv6 attempts that will always fail.
    let addrs_filter: AddrFilter = if std::env::var_os("FORCE_IPV6").is_some() {
        AddrFilter::new(|addrs| {
            use std::borrow::Cow;
            Cow::Owned(
                addrs.iter()
                    .filter(|a| matches!(a, TransportAddr::Ip(sa) if sa.is_ipv6()))
                    .cloned()
                    .collect(),
            )
        })
    } else if std::env::var_os("FORCE_IPV4_ONLY").is_some() {
        AddrFilter::new(|addrs| {
            use std::borrow::Cow;
            Cow::Owned(
                addrs.iter()
                    .filter(|a| matches!(a, TransportAddr::Ip(sa) if sa.is_ipv4()))
                    .cloned()
                    .collect(),
            )
        })
    } else {
        // Default: publish everything (public IPv4 + IPv6 + relay URL).
        // This is the key change that lets direct connections succeed.
        AddrFilter::unfiltered()
    };

    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .relay_mode(relay_mode)
        .alpns(vec![ALPN.to_vec()])
        // Try UPnP / NAT-PMP / PCP for IPv4 port mapping — does nothing if
        // the router doesn't support them or the device is already public.
        .portmapper_config(PortmapperConfig::default())
        // Add a SECOND PkarrPublisher that overrides the default relay-only
        // filter. Without this the default n0 preset *never* publishes your
        // public IPv6 to dns.iroh.link, so the client can never learn your
        // direct address and is forced to relay-only traffic.
        .address_lookup(PkarrPublisher::n0_dns().addr_filter(addrs_filter))
        .bind()
        .await?;

    let router = Router::builder(endpoint.clone())
        .accept(ALPN.to_vec(), BridgeHandler)
        .spawn();

    // Block until fully online (DNS announcements finished, relay reachable).
    endpoint.online().await;

    println!();
    println!("=========================================================");
    println!(" iroh-rdp-tunnel SERVER {BUILD_TAG}");
    println!("=========================================================");
    println!(" Copy this endpoint id into the `client` on the other machine:");
    println!();
    println!("     {}", endpoint_id);
    println!();

    // Print every address this endpoint advertises — this is exactly what
    // the client will be able to dial after it resolves the pkarr record.
    let info = endpoint.addr();
    println!(" My addresses (what we publish to DNS):");
    if info.ip_addrs().count() == 0 {
        println!("     IP  :  <none — UPnP failed AND no public IPv6 detected>");
        println!("           → client will be forced into relay-only mode (high latency)");
    } else {
        for ip in info.ip_addrs() {
            println!("     IP  : {ip}");
        }
    }
    for u in info.relay_urls() {
        println!("     Relay: {u}");
    }
    println!();
    println!(" Address-filter: ");
    if std::env::var_os("FORCE_IPV6").is_some() {
        println!("     FORCE_IPV6=1     → only IPv6 public addresses published");
    } else if std::env::var_os("FORCE_IPV4_ONLY").is_some() {
        println!("     FORCE_IPV4_ONLY=1 → only IPv4 public addresses published");
    } else {
        println!("     unfiltered         → IPv4 + IPv6 + relay URL published");
    }
    println!(" Relay mode: {}",
        if std::env::var_os("NO_RELAY").is_some() { "Disabled" } else { "Default (n0)" });
    println!();
    println!(" Now watching:");
    println!("   * Looking for `external_address`  → UPnP/portmapper succeeded");
    println!("   * Looking for `direct IPv6`        → straight-from-public-IPv6 path");
    println!("   * Looking for `home is now relay`  → currently on a relay (only)");
    println!();
    println!(" Waiting for client connection... (Ctrl-C to exit)");
    println!();

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
