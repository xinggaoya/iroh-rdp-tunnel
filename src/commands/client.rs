//! `irt client` —— 在控制端运行。
//!
//! 监听本地 `127.0.0.1:13389`（一个「假 RDP」端口），把每个进来的 TCP 连接
//! 桥接到远端被控机的 Windows RDP。
//!
//! 与远端保持**一条**常驻 QUIC 连接（见 [`crate::connmgr`]），
//! 每条本地 TCP 连接只开一条 QUIC 双向流 —— 打洞只发生一次。

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

use iroh::Watcher as _;
use tokio::net::{TcpListener, TcpStream};

use crate::{
    BUILD_TAG,
    config::ClientConfig,
    endpoint::{EndpointOptions, bind_resolver_only},
    keys::{load_or_create_secret_key, write_endpoint_id_hint},
    transport::{PeerRef, TransportEndpoint, iroh::IrohTransport},
    tunnel::bridge_tcp_to_stream,
};

/// 等待远端连接就绪的超时。
///
/// 等待本机 net report 就绪的超时。
///
/// **这个等待很关键**：打洞时客户端要用 `REACH_OUT` 帧通告自己的公网候选，
/// 而公网候选（`global_v4`）来自 net report 的 QAD 探测。
/// net report 要连上 relay、跑完多个中继的对比探测才出结果，
/// 实测比连接建立晚 24~47 秒 —— 在它就绪之前，客户端通告的候选里
/// 只有私网地址，服务端**连打洞都不会发起**（连「直连路径已打开」都没有）。
const NET_REPORT_TIMEOUT: Duration = Duration::from_secs(25);

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

    // 先等 net report 就绪，再建连 ——
    // 详见 [`NET_REPORT_TIMEOUT`] 的说明：候选地址不齐就不该开始打洞。
    {
        let mut watcher = endpoint.net_report();
        match tokio::time::timeout(NET_REPORT_TIMEOUT, watcher.initialized()).await {
            Ok(_) => {
                tracing::debug!("net report 已就绪，公网候选可用");
            }
            Err(_) => {
                tracing::warn!(
                    "net report 未在 {} 秒内就绪 —— 客户端通告的公网候选可能为空，打洞会推迟",
                    NET_REPORT_TIMEOUT.as_secs()
                );
            }
        }
    }

    // 后台立即开始建连（打洞也随之开始），不等到用户打开 mstsc。
    let transport = IrohTransport::new_client(endpoint.clone(), cfg.remote, None);
    let peer = PeerRef::Iroh(cfg.remote);

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
    // 防火墙状态 —— 打洞要**双向**，服务端打向本机的入站 UDP 会被本机防火墙拦掉。
    // 这是最容易被忽略的一环（控制端经常只顾着在被控端装规则）。
    let fw_status = match crate::fw::current_exe() {
        Ok(exe) => crate::fw::status(&exe),
        Err(_) => crate::fw::FirewallStatus::Unknown,
    };
    println!(" 防火墙        : {}", crate::fw::status_hint(fw_status));
    if !matches!(fw_status, crate::fw::FirewallStatus::Allowed) {
        println!("                 ⚠ 打洞需要**本机**放行入站 UDP！");
        println!("                   请以管理员身份执行: irt.exe client --install-firewall-rule");
    }
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
                let host = url
                    .split("//")
                    .nth(1)
                    .unwrap_or(&url)
                    .trim_end_matches(['/', '.']);
                println!(" 本端中继域名  : {host}");
                println!("                 （与被控端的中继**保持一致**可避免中继间转发）");
            }
        });
    }

    // Ctrl-C 时优雅关闭端点（否则 iroh 会报
    // "Endpoint dropped without calling close()"）。
    tokio::select! {
        r = serve_local(transport.clone(), peer, listener) => r,
        r = tokio::signal::ctrl_c() => {
            r?;
            println!("\n正在关闭…");
            transport.close().await;
            endpoint.close().await;
            Ok(())
        }
    }
}

/// 监听本地 TCP 端口，把每个进来的连接桥接到远端。
///
/// 抽出来是为了让集成测试能驱动**与生产完全相同**的这条路径
/// （本地 TCP → 常驻 QUIC 连接 → 远端）。
pub async fn serve_local(
    transport: Arc<dyn TransportEndpoint>,
    remote: PeerRef,
    listener: TcpListener,
) -> Result<()> {
    loop {
        let (tcp, tcp_peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("本地 TCP accept 失败: {e}");
                continue;
            }
        };
        tracing::info!("本地 RDP 客户端接入: {tcp_peer}");

        let transport = transport.clone();
        let remote = remote.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_session(transport, remote, tcp).await {
                tracing::warn!("会话结束: {e:#}");
            }
        });
    }
}

/// 把一条本地 TCP 连接桥接到远端。
pub async fn handle_session(
    transport: Arc<dyn TransportEndpoint>,
    peer: PeerRef,
    local: TcpStream,
) -> Result<()> {
    // 打开到远端的流（连接刚断时后端会自己重试一次）。
    let stream = transport
        .open_stream(&peer)
        .await
        .context("打开到远端的流失败")?;
    bridge_tcp_to_stream(local, stream).await.context("桥接失败")?;
    Ok(())
}
