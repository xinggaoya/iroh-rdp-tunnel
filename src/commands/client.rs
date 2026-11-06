//! `irt client` —— 在控制端运行。
//!
//! 监听本地 `127.0.0.1:13389`（一个「假 RDP」端口），把每个进来的 TCP 连接
//! 桥接到远端被控机的 Windows RDP。
//!
//! 与远端保持**一条**常驻 QUIC 连接（见 [`crate::connmgr`]），
//! 每条本地 TCP 连接只开一条 QUIC 双向流 —— 打洞只发生一次。

use std::time::Duration;

use anyhow::{Context, Result};

use tokio::net::{TcpListener, TcpStream};

use crate::{
    BUILD_TAG,
    config::ClientConfig,
    connmgr::ConnManager,
    endpoint::{EndpointOptions, bind_resolver_only},
    keys::{load_or_create_secret_key, write_endpoint_id_hint},
    tunnel::bridge_tcp_to_quic,
};

/// 等待远端连接就绪的超时。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// 运行控制端。
pub async fn run(cfg: ClientConfig) -> Result<()> {
    // 控制端也持久化自己的私钥：id 固定之后才能写进被控端的 `--allow` 白名单。
    let secret_key = load_or_create_secret_key(&cfg.key_file)?;
    let local_id = secret_key.public();

    let endpoint = bind_resolver_only(EndpointOptions {
        secret_key: Some(secret_key),
        relay_mode: cfg.relay_mode.clone(),
        publish: crate::addrpolicy::PublishPolicy::RelayOnly,
        discovery: cfg.discovery,
        portmapper: true,
        ca_tls_config: cfg.ca_tls_config.clone(),
    })
    .await?;

    // 把本机 id 也写成纯文本，方便复制到被控端的 --allow。
    let _ = write_endpoint_id_hint(&cfg.key_file, local_id);

    // 后台立即开始建连（打洞也随之开始），不等到用户打开 mstsc。
    let mgr = ConnManager::start(endpoint.clone(), cfg.remote);

    let listener = TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("无法绑定本地 TCP {}", cfg.listen))?;

    println!();
    println!("=========================================================");
    println!(" iroh-rdp-tunnel CLIENT  ({BUILD_TAG})");
    println!("=========================================================");
    println!(" 远端 endpoint : {}", cfg.remote);
    println!(" 本机 endpoint : {local_id}");
    println!("                 （可写进被控端的 --allow 白名单）");
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

    // 打印本端实际连上的中继 —— **两端必须一致**。
    // 各自自动选 relay 很容易选到不同家，流量就得先到本端的中继再转给对端的中继，
    // 多一跳，延迟直接叠加（实测见过 1152ms）。
    {
        let endpoint = endpoint.clone();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(30), endpoint.online()).await;
            if let Some(url) = crate::pathinfo::home_relay(&endpoint) {
                println!(" 本端中继      : {url}");
                println!("                 （与被控端的中继**保持一致**可避免中继间转发）");
            }
        });
    }

    // Ctrl-C 时优雅关闭端点（否则 iroh 会报
    // "Endpoint dropped without calling close()"）。
    tokio::select! {
        r = serve_local(mgr, listener) => r,
        r = tokio::signal::ctrl_c() => {
            r?;
            println!("\n正在关闭…");
            endpoint.close().await;
            Ok(())
        }
    }
}

/// 监听本地 TCP 端口，把每个进来的连接桥接到远端。
///
/// 抽出来是为了让集成测试能驱动**与生产完全相同**的这条路径
/// （本地 TCP → 常驻 QUIC 连接 → 远端）。
pub async fn serve_local(mgr: ConnManager, listener: TcpListener) -> Result<()> {
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
pub async fn handle_session(mgr: ConnManager, local: TcpStream) -> Result<()> {
    let conn = mgr.connection(CONNECT_TIMEOUT).await?;
    // 连接可能刚好在这一瞬间断开，open_bi 会失败 —— 换一条新连接重试一次。
    let (send, recv) = match conn.open_bi().await {
        Ok(s) => s,
        Err(first) => {
            tracing::warn!("打开 QUIC 双向流失败（连接可能刚断开）: {first}，重试一次");
            let conn = mgr.connection(CONNECT_TIMEOUT).await?;
            conn.open_bi()
                .await
                .context("重试后仍无法打开 QUIC 双向流")?
        }
    };
    bridge_tcp_to_quic(local, send, recv)
        .await
        .context("桥接失败")?;
    Ok(())
}
