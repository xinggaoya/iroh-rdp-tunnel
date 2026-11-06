//! `irt server` —— 在被控的 Windows 机器上运行。
//!
//! 职责：监听入站 QUIC 连接，把每条双向流桥接到本机 RDP（默认 `127.0.0.1:3389`）。
//!
//! 地址发布策略见 [`crate::addrpolicy`]：默认 **relay-only** —— 这是本机网络
//! （EIM 映射 + 地址依赖过滤）下唯一能保证建连的方式，见 `DESIGN.md` §2。

use std::net::SocketAddr;

use anyhow::Result;
use iroh::{
    Endpoint, EndpointId, RelayMode,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler, Router},
};
use tokio::net::TcpStream;

use crate::{
    ALPN, BUILD_TAG,
    config::ServerConfig,
    endpoint::{EndpointOptions, bind},
    fw::{RULE_NAME, current_exe, status, status_hint},
    keys::{load_or_create_secret_key, write_endpoint_id_hint},
    pathinfo::spawn_path_reporter,
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
    /// 本机端点 —— 用于读取 home relay（检测两端中继是否一致）。
    pub endpoint: Endpoint,
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
        spawn_path_reporter(conn.clone(), "server", self.endpoint.clone());

        loop {
            let (mut send, recv) = match conn.accept_bi().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::info!("accept 循环结束（{remote}）: {e}");
                    return Ok(());
                }
            };

            let tcp = match TcpStream::connect(self.rdp_target).await {
                Ok(t) => t,
                Err(e) => {
                    // 只关掉**这一条**流，不要拆掉整条 QUIC 连接 ——
                    // 同一连接上可能还有别的流在用。
                    tracing::warn!(
                        "本机 RDP 未在 {} 上运行: {e}（关闭本条流，连接继续服务）",
                        self.rdp_target
                    );
                    let _ = send.reset(1u32.into());
                    continue;
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
        ca_tls_config: cfg.ca_tls_config.clone(),
    })
    .await?;

    tracing::debug!("endpoint {endpoint_id} 已绑定");

    Ok(ServerRuntime {
        handler: BridgeHandler {
            rdp_target: cfg.rdp_target,
            allow_list: cfg.allow_list.clone(),
            endpoint: endpoint.clone(),
        },
        endpoint,
    })
}

/// 等 relay 连接的超时。
///
/// `Endpoint::online()` 是无界的：relay 不可达时它永远不会返回，
/// 必须套一个超时，否则 banner 永远打不出来。
pub const RELAY_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// 是否需要等待 relay 连接。
///
/// `RelayMode::Disabled` 下没有 home relay，`Endpoint::online()` 里的
/// `home_relay_status()` 永远是空 vec，`watcher.updated()` 永不返回 ——
/// 也就是说 `online()` 永远不会完成。这种情况必须跳过。
pub fn needs_relay_wait(relay_mode: &RelayMode) -> bool {
    !matches!(relay_mode, RelayMode::Disabled)
}

/// 运行被控端。
pub async fn run(cfg: ServerConfig) -> Result<()> {
    let rt = build(&cfg).await?;
    let endpoint_id = rt.endpoint.id();
    // 顺手把 id 写一份纯文本，方便用户复制。
    let _ = write_endpoint_id_hint(&cfg.key_file, endpoint_id);

    let router = Router::builder(rt.endpoint.clone())
        .accept(ALPN, rt.handler.clone())
        .spawn();

    // 先把关键信息打出来 —— endpoint id 必须**立即**可见，
    // 不能因为 relay 连不上就卡住不输出。
    print_banner_head(&cfg, endpoint_id);

    // 等 relay 连上，让 DNS 公告发出去。
    if needs_relay_wait(&cfg.relay_mode) {
        println!(" 正在连接中继…");
        match tokio::time::timeout(RELAY_WAIT_TIMEOUT, rt.endpoint.online()).await {
            Ok(()) => {}
            Err(_) => {
                println!(
                    " ⚠ {} 秒内未连上 relay —— 客户端可能暂时连不上，但服务已在监听",
                    RELAY_WAIT_TIMEOUT.as_secs()
                );
            }
        }
    }

    print_banner_network(&rt.endpoint, endpoint_id);

    println!();
    println!(" 等待客户端连接…  (Ctrl-C 退出)");
    println!();

    tokio::signal::ctrl_c().await?;
    println!("
正在关闭…");
    router.shutdown().await?;
    // Router::shutdown 会关掉 endpoint；再调一次只为避免
    // "Endpoint dropped without calling close()" 的告警。
    let _ = rt.endpoint.close().await;
    Ok(())
}

/// 打印启动横幅的关键部分（立即输出）。
fn print_banner_head(cfg: &ServerConfig, endpoint_id: EndpointId) {
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

    let fw_status = match current_exe() {
        Ok(exe) => status(&exe),
        Err(_) => crate::fw::FirewallStatus::Unknown,
    };
    println!(" 防火墙        : {}", status_hint(fw_status));
    println!("                 （规则名: {RULE_NAME}）");
}

/// 打印网络信息部分（等 relay 连上之后）。
fn print_banner_network(endpoint: &Endpoint, endpoint_id: EndpointId) {
    let addr = endpoint.addr();

    let relays: Vec<_> = addr.relay_urls().collect();
    if relays.is_empty() {
        println!(" 中继          : ⚠ 未连上任何 relay（客户端将无法建连）");
    } else {
        for u in &relays {
            println!(" 中继          : {u}");
        }
    }

    // 这些是本机**所有**网卡地址（含私网与虚拟网卡）。
    // 默认发布策略是 relay-only，所以它们并不会对外公布。
    let mut global = Vec::new();
    let mut private = Vec::new();
    for ip in addr.ip_addrs() {
        if is_global_addr(ip) {
            global.push(ip.to_string());
        } else {
            private.push(ip.to_string());
        }
    }
    if global.is_empty() && private.is_empty() {
        println!(" 本机地址      : （未探测到）");
    }
    for ip in &global {
        println!(" 本机地址      : {ip}   (公网，默认策略下不公布)");
    }
    for ip in &private {
        println!(" 本机地址      : {ip}   (私网)");
    }

    // 把客户端要跑的**完整命令**打出来。
    //
    // 两端各自自动选 relay 极易选到不同家（实测：服务端 euc1-1 欧洲、
    // 客户端 usw1-1 美西），流量就得多走一跳中继转发，RTT 从 ~400ms 涨到 1200ms。
    // 让用户直接复制这一行，就不可能漏掉 --relay。
    if let Some(relay) = relays.first() {
        println!();
        println!(" 客户端请执行（**必须带同样的 relay**，否则会多一跳中继转发）:");
        println!("   irt client {endpoint_id} --relay {relay}");
    }
}

/// 地址是否是全局可路由的。
fn is_global_addr(addr: &std::net::SocketAddr) -> bool {
    match addr {
        std::net::SocketAddr::V4(sa) => is_global_v4(*sa.ip()),
        std::net::SocketAddr::V6(sa) => {
            let ip = sa.ip();
            !ip.is_unspecified() && !ip.is_loopback() && !ip.is_unicast_link_local()
        }
    }
}

/// IPv4 是否是公网可路由地址。
///
/// `Ipv4Addr::is_global()` 还不稳定，所以这里手写判定：
/// 排除未指定、回环、链路本地、多播、广播、私有、CGNAT 共享段、
/// 文档地址段与保留段。
fn is_global_v4(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_private()
    {
        return false;
    }
    // 0.0.0.0/8
    if o[0] == 0 {
        return false;
    }
    // 100.64.0.0/10 —— CGNAT 共享地址段
    if o[0] == 100 && (64..128).contains(&o[1]) {
        return false;
    }
    // 192.0.2.0/24、198.51.100.0/24、203.0.113.0/24 —— 文档地址段
    if (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
    {
        return false;
    }
    // 240.0.0.0/4 —— 保留
    if o[0] >= 240 {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_disabled_means_no_wait() {
        assert!(!needs_relay_wait(&RelayMode::Disabled));
    }

    #[test]
    fn default_relay_mode_needs_wait() {
        assert!(needs_relay_wait(&RelayMode::Default));
    }

    #[test]
    fn global_and_private_addresses_are_distinguished() {
        let global: std::net::SocketAddr = "171.37.192.67:1234".parse().unwrap();
        let private: std::net::SocketAddr = "192.168.0.138:1234".parse().unwrap();
        let link_local_v6: std::net::SocketAddr = "[fe80::1]:1234".parse().unwrap();
        assert!(is_global_addr(&global), "公网地址应被判为 global");
        assert!(!is_global_addr(&private), "私网地址不应被判为 global");
        assert!(!is_global_addr(&link_local_v6), "链路本地 IPv6 不应被判为 global");
    }

    #[test]
    fn special_ipv4_ranges_are_not_global() {
        for s in [
            "0.0.0.0",
            "127.0.0.1",
            "169.254.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "100.64.0.1", // CGNAT
            "192.0.2.1",  // 文档
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
        ] {
            let ip: std::net::SocketAddr = format!("{s}:1").parse().unwrap();
            assert!(!is_global_addr(&ip), "{s} 不应被判为 global");
        }
    }

    #[test]
    fn relay_wait_timeout_is_bounded() {
        assert!(RELAY_WAIT_TIMEOUT > std::time::Duration::from_secs(0));
        assert!(RELAY_WAIT_TIMEOUT <= std::time::Duration::from_secs(60));
    }
}
