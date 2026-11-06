//! `irt client` —— 在控制端运行。
//!
//! 监听本地 `127.0.0.1:13389`（一个「假 RDP」端口），把每个进来的 TCP 连接
//! 桥接到远端被控机的 Windows RDP。
//!
//! 与远端保持**一条**常驻 QUIC 连接（见 [`crate::connmgr`]），
//! 每条本地 TCP 连接只开一条 QUIC 双向流 —— 打洞只发生一次。

use std::time::Duration;

use anyhow::{Context, Result};
use iroh::{Endpoint, address_lookup::DnsAddressLookup, endpoint::presets};
use tokio::net::{TcpListener, TcpStream};

use crate::{
    ALPN, BUILD_TAG,
    config::ClientConfig,
    connmgr::ConnManager,
    tunnel::bridge_tcp_to_quic,
};

/// 等待远端连接就绪的超时。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// 运行控制端。
pub async fn run(cfg: ClientConfig) -> Result<()> {
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(cfg.relay_mode.clone())
        .alpns(vec![ALPN.to_vec()])
        // 客户端不需要被拨通，因此不发布自己的地址；只需要能**解析**远端。
        .address_lookup(DnsAddressLookup::n0_dns())
        .bind()
        .await?;

    // 后台立即开始建连（打洞也随之开始），不等到用户打开 mstsc。
    let mgr = ConnManager::start(endpoint, cfg.remote);

    let listener = TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("无法绑定本地 TCP {}", cfg.listen))?;

    println!();
    println!("=========================================================");
    println!(" iroh-rdp-tunnel CLIENT  ({BUILD_TAG})");
    println!("=========================================================");
    println!(" 远端 endpoint : {}", cfg.remote);
    println!(" 本地 TCP 监听 : {}", cfg.listen);
    println!();
    println!(" 正在与远端建立连接…");
    println!();
    println!(" 用系统自带的远程桌面连接本机端口:");
    println!("     Windows : mstsc /v:{}", cfg.listen);
    println!("     Mac     : Microsoft Remote Desktop → 地址填 {}", cfg.listen);
    println!("     手机    : RD Client → 地址填 {}", cfg.listen);
    println!(" (Ctrl-C 退出)");
    println!();

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("本地 TCP accept 失败: {e}");
                continue;
            }
        };
        tracing::info!("本地 RDP 客户端接入: {peer}");

        let mgr = mgr.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_session(mgr, tcp).await {
                tracing::warn!("会话结束: {e:#}");
            }
        });
    }
}

/// 把一条本地 TCP 连接桥接到远端。
async fn handle_session(mgr: ConnManager, local: TcpStream) -> Result<()> {
    let conn = mgr.connection(CONNECT_TIMEOUT).await?;
    let (send, recv) = conn.open_bi().await.context("无法打开 QUIC 双向流")?;
    bridge_tcp_to_quic(local, send, recv)
        .await
        .context("桥接失败")?;
    Ok(())
}
