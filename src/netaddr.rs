//! 公网地址判定 —— 区分「可对外打洞的公网端点」与「局域网/链路本地地址」。
//!
//! `Ipv4Addr::is_global()` 在 Rust 标准库里还是 unstable（`ip` feature），
//! 所以这里按 RFC 6890 的特殊用途地址段手工判定。
//!
//! 为什么需要它：iroh 的路径事件里会同时冒出本机的私网地址
//! （多张虚拟网卡、回环、链路本地）和真正的公网端点。
//! 打洞关心的是**公网端点**，私网地址的开关纯属噪音。

use std::net::{Ipv4Addr, Ipv6Addr};

/// IPv4 是否为可对外打洞的公网地址。
///
/// 排除：0/8、10/8、100.64/10（CGNAT 共享段）、127/8、169.254/16、
/// 172.16/12、192.0.0/24、192.168/16、198.18/15、198.51.100/24、
/// 203.0.113/24、224/4（多播）、240/4（保留）。
pub fn is_global_v4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    match o {
        // 0.0.0.0/8
        [0, ..] => false,
        // 10.0.0.0/8
        [10, ..] => false,
        // 100.64.0.0/10 —— CGNAT 共享地址段
        [100, 64..=127, ..] => false,
        // 127.0.0.0/8
        [127, ..] => false,
        // 169.254.0.0/16
        [169, 254, ..] => false,
        // 172.16.0.0/12
        [172, 16..=31, ..] => false,
        // 192.0.0.0/24
        [192, 0, 0, ..] => false,
        // 192.168.0.0/16
        [192, 168, ..] => false,
        // 198.18.0.0/15
        [198, 18..=19, ..] => false,
        // 198.51.100.0/24
        [198, 51, 100, ..] => false,
        // 203.0.113.0/24
        [203, 0, 113, ..] => false,
        // 224.0.0.0/4 多播、240.0.0.0/4 保留（含广播）
        [224..=255, ..] => false,
        _ => true,
    }
}

/// IPv6 是否为可对外打洞的全局地址。
///
/// 排除：未指定、回环、链路本地（fe80::/10）、ULA（fc00::/7）、多播（ff00::/8），
/// 以及 IPv4-mapped 地址（::ffff:0:0/96）—— 后者按内嵌的 IPv4 判定。
pub fn is_global_v6(ip: &Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() {
        return false;
    }
    // 链路本地 fe80::/10
    if ip.segments()[0] & 0xffc0 == 0xfe80 {
        return false;
    }
    // ULA fc00::/7
    if ip.segments()[0] & 0xfe00 == 0xfc00 {
        return false;
    }
    // 多播 ff00::/8
    if ip.segments()[0] & 0xff00 == 0xff00 {
        return false;
    }
    // IPv4-mapped ::ffff:a.b.c.d
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_global_v4(&v4);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_ipv4_is_global() {
        assert!(is_global_v4(&"171.37.192.67".parse().unwrap()));
        assert!(is_global_v4(&"8.8.8.8".parse().unwrap()));
        assert!(is_global_v4(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn private_and_special_ipv4_is_not_global() {
        for s in [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",  // CGNAT
            "100.127.255.255",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.1",
            "192.168.0.138",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(
                !is_global_v4(&s.parse().unwrap()),
                "{s} 不该被当成公网地址"
            );
        }
    }

    #[test]
    fn global_ipv6_is_global() {
        assert!(is_global_v6(&"2408:845d:102:6406::1".parse().unwrap()));
        assert!(is_global_v6(&"2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn special_ipv6_is_not_global() {
        for s in [
            "::",
            "::1",
            "fe80::1",
            "fc00::1",       // ULA
            "fd12:3456::1",  // ULA
            "ff02::1",       // 多播
            "::ffff:192.168.0.1", // IPv4-mapped 私网
        ] {
            assert!(
                !is_global_v6(&s.parse().unwrap()),
                "{s} 不该被当成公网地址"
            );
        }
    }

    #[test]
    fn ipv4_mapped_public_is_global() {
        assert!(is_global_v6(&"::ffff:171.37.192.67".parse().unwrap()));
    }
}
