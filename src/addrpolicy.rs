//! 发布策略：决定 server 对外（pkarr/DNS）公布哪些地址。
//!
//! 这是整个项目里最关键的一个开关，原因见 `DESIGN.md` §2：
//!
//! - iroh 的打洞基于 QUIC NAT Traversal 扩展，**候选地址在已建立的 QUIC 连接上交换**；
//! - 而 relay 路径**必须**来自对端公布的 `RelayUrl`；
//! - 所以在「地址依赖过滤」的 NAT 后面，若不公布 relay URL，客户端连初始连接都建不起来，
//!   也就没有通道去交换打洞候选 —— 直连永远不可能发生。

use iroh::{TransportAddr, address_lookup::AddrFilter};

/// server 对外公布哪些地址。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishPolicy {
    /// 只公布 relay URL —— iroh 标准模型：先经 relay 建连，再双方同时打洞迁移到直连。
    RelayOnly,
    /// 只公布公网 IP —— 需要对端做了端口转发/静态映射时使用。
    IpOnly,
    /// 只公布公网 IPv6 地址（遗留 `FORCE_IPV6=1` 的等价物）。
    IpV6Only,
    /// relay URL 与公网 IP 全部公布。
    All,
}

impl PublishPolicy {
    /// 解析命令行/环境变量里的策略名，接受 `relay` / `ip` / `ipv6` / `all`（大小写不敏感）。
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "relay" => Ok(Self::RelayOnly),
            "ip" => Ok(Self::IpOnly),
            "ipv6" => Ok(Self::IpV6Only),
            "all" => Ok(Self::All),
            other => anyhow::bail!("未知的发布策略 `{other}`（可选值：relay / ip / ipv6 / all）"),
        }
    }

    /// 策略的规范名称。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RelayOnly => "relay",
            Self::IpOnly => "ip",
            Self::IpV6Only => "ipv6",
            Self::All => "all",
        }
    }

    /// 映射到 iroh 的地址过滤器。
    pub fn to_addr_filter(self) -> AddrFilter {
        match self {
            Self::RelayOnly => AddrFilter::relay_only(),
            Self::IpOnly => AddrFilter::ip_only(),
            Self::IpV6Only => AddrFilter::new(|addrs| {
                use std::borrow::Cow;
                Cow::Owned(
                    addrs
                        .iter()
                        .filter(|a| match a {
                            TransportAddr::Ip(sa) => match sa {
                                std::net::SocketAddr::V4(_) => false,
                                std::net::SocketAddr::V6(sa6) => is_global_ipv6(&sa6.ip()),
                            },
                            _ => false,
                        })
                        .cloned()
                        .collect(),
                )
            }),
            Self::All => AddrFilter::unfiltered(),
        }
    }
}

/// 是否为可对外公布的全局 IPv6 地址（排除未指定、回环、链路本地）。
fn is_global_ipv6(ip: &std::net::Ipv6Addr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_unicast_link_local()
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::{RelayUrl, TransportAddr};

    fn sample_addrs() -> Vec<TransportAddr> {
        let relay: RelayUrl = "https://aps1-1.relay.n0.iroh.link.".parse().unwrap();
        vec![
            TransportAddr::Ip("171.37.192.67:34622".parse().unwrap()),
            TransportAddr::Ip("[fe80::1]:9000".parse().unwrap()),
            TransportAddr::Ip("[2400:8a00::1]:9000".parse().unwrap()),
            TransportAddr::Relay(relay),
        ]
    }

    fn kinds(addrs: &[TransportAddr]) -> Vec<&'static str> {
        addrs.iter()
            .map(|a| match a {
                TransportAddr::Ip(_) => "ip",
                TransportAddr::Relay(_) => "relay",
                _ => "custom",
            })
            .collect()
    }

    #[test]
    fn parse_accepts_all_three_names() {
        assert_eq!(PublishPolicy::parse("relay").unwrap(), PublishPolicy::RelayOnly);
        assert_eq!(PublishPolicy::parse("ip").unwrap(), PublishPolicy::IpOnly);
        assert_eq!(PublishPolicy::parse("all").unwrap(), PublishPolicy::All);
    }

    #[test]
    fn parse_accepts_ipv6_legacy_name() {
        assert_eq!(
            PublishPolicy::parse("ipv6").unwrap(),
            PublishPolicy::IpV6Only
        );
    }

    #[test]
    fn ipv6_only_keeps_only_global_ipv6_addresses() {
        let addrs = sample_addrs();
        let out = PublishPolicy::IpV6Only.to_addr_filter().apply(&addrs);
        // 只保留全局 IPv6（2400:8a00::1）；链路本地 fe80::1、IPv4、relay 全部丢弃。
        assert_eq!(kinds(&out), vec!["ip"]);
        match &out[0] {
            TransportAddr::Ip(sa) => {
                assert_eq!(sa.to_string(), "[2400:8a00::1]:9000");
            }
            other => panic!("期望 IPv6 地址，实际: {other:?}"),
        }
    }

    #[test]
    fn parse_is_case_insensitive_and_trims() {
        assert_eq!(PublishPolicy::parse("RELAY").unwrap(), PublishPolicy::RelayOnly);
        assert_eq!(PublishPolicy::parse(" All ").unwrap(), PublishPolicy::All);
    }

    #[test]
    fn parse_rejects_unknown_value_and_mentions_it() {
        let err = PublishPolicy::parse("banana").unwrap_err().to_string();
        assert!(err.contains("banana"), "错误信息应包含非法值，实际: {err}");
    }

    #[test]
    fn as_str_round_trips_through_parse() {
        for p in [PublishPolicy::RelayOnly, PublishPolicy::IpOnly, PublishPolicy::All] {
            assert_eq!(PublishPolicy::parse(p.as_str()).unwrap(), p);
        }
    }

    #[test]
    fn relay_only_keeps_only_the_relay_address() {
        let addrs = sample_addrs();
        let out = PublishPolicy::RelayOnly.to_addr_filter().apply(&addrs);
        assert_eq!(kinds(&out), vec!["relay"]);
    }

    #[test]
    fn ip_only_drops_the_relay_address() {
        let addrs = sample_addrs();
        let out = PublishPolicy::IpOnly.to_addr_filter().apply(&addrs);
        assert_eq!(kinds(&out), vec!["ip", "ip", "ip"]);
    }

    #[test]
    fn all_keeps_everything() {
        let addrs = sample_addrs();
        let out = PublishPolicy::All.to_addr_filter().apply(&addrs);
        assert_eq!(kinds(&out), vec!["ip", "ip", "ip", "relay"]);
    }
}
