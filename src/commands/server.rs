//! `irt server` —— 在被控的 Windows 机器上运行。
//!
//! 职责：监听入站 QUIC 连接，把每条双向流桥接到本机 RDP（默认 `127.0.0.1:3389`）。
//!
//! 地址发布策略见 [`crate::addrpolicy`]：默认 **relay-only** —— 这是本机网络
//! （EIM 映射 + 地址依赖过滤）下唯一能保证建连的方式，见 `DESIGN.md` §2。

use std::net::SocketAddr;

use anyhow::Result;
use iroh::{Endpoint, EndpointId, RelayMode, Watcher as _};
use tokio::net::TcpStream;

use crate::{
    BUILD_TAG,
    config::ServerConfig,
    endpoint::{EndpointOptions, bind},
    fw::{RULE_NAME, current_exe, status, status_hint},
    keys::{load_or_create_secret_key, write_endpoint_id_hint},
    transport::{TransportEndpoint, iroh::IrohTransport},
    tunnel::bridge_stream_to_tcp,
};

/// 被控端运行时。
///
/// 拆成运行时与执行循环是为了让集成测试能直接拿到 [`Endpoint`] 与传输端点，
/// 自己驱动 accept，而不必走完整的进程流程。
pub struct ServerRuntime {
    /// 已绑定、已连上 relay 的 iroh 端点。
    pub endpoint: Endpoint,
    /// 传输层端点 —— 负责接受入站连接并把流交出来。
    pub transport: std::sync::Arc<dyn TransportEndpoint>,
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

    let transport = IrohTransport::new_server(endpoint.clone(), cfg.allow_list.clone());

    Ok(ServerRuntime {
        endpoint,
        transport,
    })
}

/// 接受入站流并桥接到本机 RDP。
///
/// 每条流一个任务：一条流坏了不影响别的流，也不影响整条连接。
pub async fn serve(
    transport: std::sync::Arc<dyn TransportEndpoint>,
    rdp_target: SocketAddr,
) -> Result<()> {
    loop {
        let accepted = match transport.accept_stream().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("接受入站流失败: {e}");
                return Err(e);
            }
        };

        tokio::spawn(async move {
            let tcp = match TcpStream::connect(rdp_target).await {
                Ok(t) => t,
                Err(e) => {
                    // 只关掉**这一条**流，不要拆掉整条连接 ——
                    // 同一连接上可能还有别的流在用。
                    tracing::warn!(
                        "本机 RDP 未在 {} 上运行: {e}（关闭本条流，连接继续服务）",
                        rdp_target
                    );
                    return;
                }
            };

            if let Err(e) = bridge_stream_to_tcp(accepted.stream, tcp).await {
                tracing::warn!("桥接结束: {e}");
            }
        });
    }
}

/// 等 relay 连接的超时。
///
/// `Endpoint::online()` 是无界的：relay 不可达时它永远不会返回，
/// 必须套一个超时，否则 banner 永远打不出来。
pub const RELAY_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// 等待 net report 就绪的超时。
///
/// net report 里的公网候选（`global_v4`）是打洞的**前提**：
/// 服务端要通过 `ADD_ADDRESS` 帧把候选地址发给客户端，客户端才知道往哪儿打。
/// net report 要连上 relay、跑完多个中继的 QAD 对比才出结果，
/// 实测比连接建立晚 24~47 秒。
pub const NET_REPORT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(25);

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

    // 传输层已经在 `build()` 里把 Router 跑起来了，
    // 这里只需要在后台把入站流桥到本机 RDP。
    let accept_task = tokio::spawn({
        let transport = rt.transport.clone();
        async move { serve(transport, cfg.rdp_target).await }
    });

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

    // 等 net report 就绪 —— 它的公网候选（`global_v4`）要通过 `ADD_ADDRESS`
    // 帧发给客户端，客户端才知道往哪儿打洞。没就绪就接受连接的话，
    // 客户端拿到的服务端候选为空，打洞必然无果。
    {
        let mut watcher = rt.endpoint.net_report();
        match tokio::time::timeout(NET_REPORT_TIMEOUT, watcher.initialized()).await {
            Ok(_) => {
                tracing::debug!("net report 已就绪，公网候选可用");
            }
            Err(_) => {
                tracing::warn!(
                    "net report 未在 {} 秒内就绪 —— 通告出去的公网候选可能为空，打洞会推迟",
                    NET_REPORT_TIMEOUT.as_secs()
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
    accept_task.abort();
    rt.transport.close().await;
    // transport.close() 会关掉 endpoint；再调一次只为避免
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
        println!(" 中继域名      : ⚠ 未连上任何 relay（客户端将无法建连）");
    } else {
        for u in &relays {
            // 域名单独一行，便于一眼看清 / 核对两端用的是不是同一个。
            let host = u.host_str().unwrap_or("").trim_end_matches('.');
            println!(" 中继域名      : {host}");
            println!(" 中继 URL      : {u}");
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
        println!(" ╔══════════════════════════════════════════════════════╗");
        println!(" ║  控制端请直接复制下面这一行（--relay 必须与本机一致）  ║");
        println!(" ╚══════════════════════════════════════════════════════╝");
        println!("   irt client {endpoint_id} --relay {relay}");
        println!();
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
