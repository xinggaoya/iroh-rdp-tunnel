//! `irt server` —— 在被控的 Windows 机器上运行。
//!
//! 职责：监听入站 QUIC 连接，把每条双向流桥接到本机 RDP（默认 `127.0.0.1:3389`）。
//!
//! 地址发布策略见 [`crate::addrpolicy`]：默认 **relay-only** —— 这是本机网络
//! （EIM 映射 + 地址依赖过滤）下唯一能保证建连的方式，见 `DESIGN.md` §2。

use std::net::SocketAddr;

use anyhow::Result;
use iroh::{
    Endpoint, EndpointId,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler, Router},
};
use tokio::net::TcpStream;

use crate::{
    ALPN, BUILD_TAG,
    config::ServerConfig,
    endpoint::{EndpointOptions, bind},
    keys::{load_or_create_secret_key, write_endpoint_id_hint},
    tunnel::bridge_quic_to_tcp,
};

/// 被控端运行时。
///
/// 拆成运行时与执行循环是为了让集成测试能直接拿到 [`Endpoint`] 与处理器，
/// 自己驱动 accept，而不必走完整的进程流程。
pub struct ServerRuntime {
    /// 已绑定、已连上 relay 的 iroh 端点。
    pub endpoint: Endpoint,
    /// 把 QUIC 流桥到本机 RDP 的协议处理器。
    pub handler: BridgeHandler,
}

/// 协议处理器：把每条入站 QUIC 双向流桥到本机 RDP。
#[derive(Debug, Clone)]
pub struct BridgeHandler {
    /// 本机 RDP 地址。
    pub rdp_target: SocketAddr,
    /// 允许接入的 endpoint id 白名单；空表示不限制。
    pub allow_list: Vec<EndpointId>,
}

impl ProtocolHandler for BridgeHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let remote = conn.remote_id();

        if !self.allow_list.is_empty() && !self.allow_list.contains(&remote) {
            let msg = format!("endpoint {remote} 不在白名单内，拒绝接入");
            tracing::warn!("{msg}");
            return Err(AcceptError::from(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                msg,
            )));
        }

        tracing::info!("收到来自 {remote} 的连接");

        loop {
            let (send, recv) = match conn.accept_bi().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::info!("accept 循环结束（{remote}）: {e}");
                    return Ok(());
                }
            };

            let tcp = match TcpStream::connect(self.rdp_target).await {
                Ok(t) => t,
                Err(e) => {
                    let msg = format!(
                        "本机 RDP 未在 {} 上运行: {e}",
                        self.rdp_target
                    );
                    tracing::warn!("{msg}");
                    return Err(AcceptError::from(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        msg,
                    )));
                }
            };

            tokio::spawn(async move {
                if let Err(e) = bridge_quic_to_tcp(send, recv, tcp).await {
                    tracing::warn!("桥接结束: {e}");
                }
            });
        }
    }
}

/// 组装被控端运行时：加载密钥、绑定端点、连上 relay。
pub async fn build(cfg: &ServerConfig) -> Result<ServerRuntime> {
    let secret_key = load_or_create_secret_key(&cfg.key_file)?;
    let endpoint_id = secret_key.public();

    let endpoint = bind(EndpointOptions {
        secret_key: Some(secret_key),
        relay_mode: cfg.relay_mode.clone(),
        publish: cfg.publish,
        discovery: cfg.discovery,
        portmapper: true,
        tls_trust: cfg.tls_trust,
    })
    .await?;

    tracing::debug!("endpoint {endpoint_id} 已绑定");

    Ok(ServerRuntime {
        handler: BridgeHandler {
            rdp_target: cfg.rdp_target,
            allow_list: cfg.allow_list.clone(),
        },
        endpoint,
    })
}

/// 运行被控端。
pub async fn run(cfg: ServerConfig) -> Result<()> {
    let rt = build(&cfg).await?;
    let endpoint_id = rt.endpoint.id();
    // 顺手把 id 写一份纯文本，方便用户复制。
    let _ = write_endpoint_id_hint(&cfg.key_file, endpoint_id);

    let router = Router::builder(rt.endpoint.clone())
        .accept(ALPN.to_vec(), rt.handler.clone())
        .spawn();

    // 等 relay 连上、DNS 公告发出，addr 才是完整的。
    rt.endpoint.online().await;

    print_banner(&cfg, &rt.endpoint, endpoint_id);

    tokio::signal::ctrl_c().await?;
    println!("\n正在关闭…");
    router.shutdown().await?;
    Ok(())
}

/// 打印启动横幅。
fn print_banner(cfg: &ServerConfig, endpoint: &Endpoint, endpoint_id: EndpointId) {
    let addr = endpoint.addr();

    println!();
    println!("=========================================================");
    println!(" iroh-rdp-tunnel SERVER  ({BUILD_TAG})");
    println!("=========================================================");
    println!(" endpoint id   : {endpoint_id}");
    println!(" 密钥文件      : {}", cfg.key_file.display());
    println!(" 发布策略      : {}", cfg.publish.as_str());
    match cfg.publish {
        crate::addrpolicy::PublishPolicy::RelayOnly => {
            println!("                 → 只公布 relay URL：客户端经 relay 建连后，");
            println!("                   双方同时发包打洞，成功后自动迁移到直连");
        }
        crate::addrpolicy::PublishPolicy::IpOnly => {
            println!("                 → 只公布公网 IP：对端必须能做端口映射，否则连不上");
        }
        crate::addrpolicy::PublishPolicy::IpV6Only => {
            println!("                 → 只公布全局 IPv6 地址");
        }
        crate::addrpolicy::PublishPolicy::All => {
            println!("                 → relay URL 与公网 IP 全部公布");
        }
    }
    println!(" RDP 目标      : {}", cfg.rdp_target);
    if cfg.allow_list.is_empty() {
        println!(" 接入白名单    : （未启用，任何 endpoint id 均可接入）");
    } else {
        println!(" 接入白名单    : {} 个 endpoint id", cfg.allow_list.len());
    }

    let relays: Vec<_> = addr.relay_urls().collect();
    if relays.is_empty() {
        println!(" 中继          : ⚠ 未连上任何 relay（客户端将无法建连）");
    } else {
        for u in relays {
            println!(" 中继          : {u}");
        }
    }

    let ips: Vec<_> = addr.ip_addrs().collect();
    if ips.is_empty() {
        println!(" 本机公网端点  : （未探测到，仅 relay 可达）");
    } else {
        for ip in ips {
            println!(" 本机公网端点  : {ip}");
        }
    }
    println!();
    println!(" 等待客户端连接…  (Ctrl-C 退出)");
    println!();
}
