//! NAT 画像与「是否预期能 P2P 直连」的判定。
//!
//! 数据来源是 iroh 的 net report（`Endpoint::net_report()`），它会做 RFC5780 风格的探测：
//! 用同一个本地端口去连多个不同的服务器，看**公网映射端点是否随目标变化**。
//!
//! ## 能测什么、不能测什么
//!
//! - **映射行为**（EIM / 对称）：能测。这决定通告出去的公网端点稳不稳定。
//! - **过滤行为**（地址依赖 / 端点无关）：**测不了**。iroh 没有这个探测能力。
//!   但这不影响结论 —— iroh 的打洞走「双方同时发包」，本来就不需要 NAT 放行任意来源的入站。
//!   所以本模块**不会**编造过滤行为的结论，只会如实标注「未测量」。

use std::{
    net::{SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use iroh::{RelayUrl, unstable_net_report::NetReport};

use crate::{portmap::PortMappingStatus, transport::TransportKind};

/// NAT 映射行为。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingBehavior {
    /// 端点无关映射（EIM）：同一个内端口始终映射到同一个公网端点。
    EndpointIndependent,
    /// 对称 NAT：映射随目标变化。
    Symmetric,
    /// 无法判定。
    Unknown,
}

impl MappingBehavior {
    /// 中文标签。
    pub fn label(self) -> &'static str {
        match self {
            MappingBehavior::EndpointIndependent => "端点无关映射 (EIM)",
            MappingBehavior::Symmetric => "对称 NAT（映射随目标变化）",
            MappingBehavior::Unknown => "未知",
        }
    }
}

/// 本机 NAT 画像。
#[derive(Debug, Clone)]
pub struct NatProfile {
    /// 公网 IPv4 端点。
    pub global_v4: Option<SocketAddrV4>,
    /// 公网 IPv6 端点。
    pub global_v6: Option<SocketAddrV6>,
    /// 映射行为。
    pub mapping: MappingBehavior,
    /// IPv4 UDP 是否可用。
    pub udp_v4: bool,
    /// IPv6 UDP 是否可用。
    pub udp_v6: bool,
    /// 是否疑似运营商门户。
    pub captive_portal: Option<bool>,
    /// 延迟最低的中继（来自探测）。
    pub preferred_relay: Option<RelayUrl>,
    /// 实际选定的 home relay（流量真正会走的那个）。
    pub home_relay: Option<RelayUrl>,
    /// 各中继的延迟。
    pub relay_latencies: Vec<(RelayUrl, Duration)>,
    /// 端口映射（UPnP / NAT-PMP / PCP）状态。
    pub port_mapping: PortMappingStatus,
    /// 传输后端 —— 决定「对称 NAT 能不能打洞」的结论。
    ///
    /// **同一个 NAT，两个后端的结论完全相反**：
    /// - iroh：对称 NAT ⇒ 打洞候选只来自 QAD ⇒ 对不上号 ⇒ 必败
    /// - rustp2p：对称 NAT ⇒ 端口预测 + 穷举 ⇒ 有机会成
    pub transport: TransportKind,
    /// 对称 NAT 的端口分配范围（0 = 未知）。
    ///
    /// 这是**端口预测**的候选空间大小 —— 范围越小越容易猜中。
    pub port_range: u16,
    /// 已知的公网 UDP 映射地址。
    pub mapping_udp: Vec<String>,
}

/// 从 iroh 的 net report 解析 NAT 画像。
pub fn profile_from_report(report: &NetReport, pm: PortMappingStatus) -> NatProfile {
    // 优先看 IPv4：`Report::mapping_varies_by_dest()` 会把 v4/v6 用 `||` 合并，
    // 「v4 是 EIM、v6 是对称」会被合并成「对称」。而本机（以及绝大多数 IPv4 出口）
    // 的实际流量走 IPv4，所以以 IPv4 的结论为准。
    let mapping = match (
        report.mapping_varies_by_dest_ipv4,
        report.mapping_varies_by_dest_ipv6,
    ) {
        (Some(v4), _) => {
            if v4 {
                MappingBehavior::Symmetric
            } else {
                MappingBehavior::EndpointIndependent
            }
        }
        (None, Some(v6)) => {
            if v6 {
                MappingBehavior::Symmetric
            } else {
                MappingBehavior::EndpointIndependent
            }
        }
        (None, None) => MappingBehavior::Unknown,
    };

    // 同一个中继可能被多种探针测到，只保留最快的那个延迟。
    let mut relay_latencies: Vec<(RelayUrl, Duration)> = Vec::new();
    for (_probe, url, latency) in report.relay_latency.iter() {
        match relay_latencies.iter_mut().find(|(u, _)| u == url) {
            Some((_, existing)) => {
                if latency < *existing {
                    *existing = latency;
                }
            }
            None => relay_latencies.push((url.clone(), latency)),
        }
    }
    relay_latencies.sort_by_key(|a| a.1);

    NatProfile {
        global_v4: report.global_v4,
        global_v6: report.global_v6,
        mapping,
        udp_v4: report.udp_v4,
        udp_v6: report.udp_v6,
        captive_portal: report.captive_portal,
        preferred_relay: report.preferred_relay.clone(),
        home_relay: None,
        relay_latencies,
        port_mapping: pm,
        transport: TransportKind::Iroh,
        port_range: 0,
        mapping_udp: Vec::new(),
    }
}

/// 从 rustp2p 的 NAT 观测构造画像。
///
/// rustp2p 的观测比 iroh 的 net report **更适合打洞**：
/// 它同时给出 NAT 类型、公网 IP、公网映射端口集合，以及
/// **端口分配范围**（`public_port_range`）—— 后者正是端口预测的候选空间。
pub fn profile_from_rustp2p(
    info: &rustp2p_quic::NatInfo,
    pm: PortMappingStatus,
) -> NatProfile {
    // `NatType::is_cone()` —— 避免直接引用 rustp2p_core 的枚举类型。
    let mapping = if info.nat_type.is_cone() {
        MappingBehavior::EndpointIndependent
    } else {
        MappingBehavior::Symmetric
    };

    // `mapping_udp_addr` 是**实际观测到的公网 UDP 端点**，
    // 比 `public_ips` + `public_udp_ports` 的拼接更可靠
    // （后者在某些情况下会是空的）。
    let mapping_udp: Vec<String> = info
        .mapping_udp_addr
        .iter()
        .map(|a| a.to_string())
        .collect();

    let global_v4 = info
        .mapping_udp_addr
        .iter()
        .find(|a| a.is_ipv4())
        .map(|a| match a.ip() {
            std::net::IpAddr::V4(v4) => SocketAddrV4::new(v4, a.port()),
            std::net::IpAddr::V6(_) => unreachable!("已按 is_ipv4 过滤"),
        })
        .or_else(|| {
            info.public_ips.first().map(|ip| {
                SocketAddrV4::new(*ip, info.public_udp_ports.first().copied().unwrap_or(0))
            })
        });

    // `public_ipv4_addr()` 是 rustp2p 官方���拼接方法。
    let public_v4_addrs = info.public_ipv4_addr();
    let udp_v4 = global_v4.is_some() || !public_v4_addrs.is_empty() || !info.public_ips.is_empty();
    let global_v4 = global_v4.or_else(|| {
        public_v4_addrs
            .iter()
            .find(|a| a.is_ipv4())
            .map(|a| match a.ip() {
                std::net::IpAddr::V4(v4) => SocketAddrV4::new(v4, a.port()),
                std::net::IpAddr::V6(_) => unreachable!("已按 is_ipv4 过滤"),
            })
    });

    NatProfile {
        global_v4,
        global_v6: info.ipv6.map(|ip| SocketAddrV6::new(ip, 0, 0, 0)),
        mapping,
        udp_v4,
        udp_v6: info.ipv6.is_some(),
        captive_portal: None,
        preferred_relay: None,
        home_relay: None,
        relay_latencies: Vec::new(),
        port_mapping: pm,
        transport: TransportKind::Rustp2p,
        port_range: info.public_port_range,
        mapping_udp,
    }
}

/// 直连预期。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expectation {
    /// 预期能 P2P 直连。
    Direct,
    /// 预期只能走中继。
    RelayOnly,
    /// 预期能直连，但要靠**端口穷举**（对称 NAT + rustp2p 后端）。
    ///
    /// 与 [`Expectation::Direct`] 的区别：直连不保证成功，
    /// 取决于端口范围的大小与运气；失败时会自动回落到中继。
    DirectViaScanning,
    /// 未能判定（探测未完成或映射行为未知）。
    Unknown,
}

impl Expectation {
    /// 一句话结论。
    pub fn headline(self) -> &'static str {
        match self {
            Expectation::Direct => "✅ 具备 P2P 直连条件",
            Expectation::RelayOnly => "❌ 直连条件不足，预计只能走中继",
            Expectation::DirectViaScanning => {
                "🟡 直连有戏但要靠端口穷举 —— 打不成会自动回落到中继"
            }
            Expectation::Unknown => "⚠️ 未能判定 —— 探测可能未完成，请重跑 irt diag",
        }
    }

    /// 机器可读的名字。
    pub fn as_str(self) -> &'static str {
        match self {
            Expectation::Direct => "direct",
            Expectation::RelayOnly => "relay-only",
            Expectation::DirectViaScanning => "direct-via-scanning",
            Expectation::Unknown => "unknown",
        }
    }
}

/// 判定结论。
#[derive(Debug, Clone)]
pub struct Verdict {
    /// 直连预期。
    pub expectation: Expectation,
    /// 是否预期能 P2P 直连（`Expectation::Unknown` 时为 false）。
    pub ok: bool,
    /// 一句话结论。
    pub headline: String,
    /// 依据。
    pub reasons: Vec<String>,
    /// 建议动作。
    pub advice: Vec<String>,
}

/// 根据 NAT 画像给出判定。
pub fn verdict(profile: &NatProfile) -> Verdict {
    let mut reasons = Vec::new();
    let mut advice = Vec::new();

    let expectation = match profile.mapping {
        MappingBehavior::EndpointIndependent => {
            reasons.push(
                "映射为 EIM（端点无关映射）⇒ 公网端点稳定，可通告，对端能对上号".into(),
            );
            Expectation::Direct
        }
        MappingBehavior::Symmetric => match profile.transport {
            TransportKind::Iroh => {
                reasons.push(
                    "映射随目标变化（对称 NAT）⇒ 通告出去的公网端点对不上号，iroh 打洞必败".into(),
                );
                reasons.push(
                    "原因：iroh 1.0.2 的打洞候选**只能**来自 QAD（对中继观测到的公网端点），而对称 NAT 下「对中继的映射」≠「对服务端的映射」；QUIC 的 observed address 报告虽能修正，iroh 尚未启用也未暴露"
                        .into(),
                );
                advice.push(
                    "只能走中继；或在路由器上手工把内网 UDP 端口固定转发出去（端口固定 ⇒ 映射与目标无关 ⇒ 变回 EIM ⇒ 打洞可成）；或改用 --transport rustp2p（端口预测 + 穷举，可破对称 NAT）"
                        .into(),
                );
                Expectation::RelayOnly
            }
            TransportKind::Rustp2p => {
                reasons.push(
                    "映射随目标变化（对称 NAT）⇒ iroh 打洞必败，但 rustp2p 靠「端口预测 + 全局随机扫描」可以破".into(),
                );
                match profile.port_range {
                    0 => {
                        reasons.push("未测得端口范围 ⇒ 穷举空间未知，打洞可能较慢".into());
                        advice.push(
                            "STUN 服务器不可达时会拿不到端口范围 —— 检查网络能否访问 UDP 3478".into(),
                        );
                    }
                    r if r <= 1000 => {
                        reasons.push(format!(
                            "对称 NAT 端口范围约 {r} 个端口 ⇒ 候选空间小，端口预测命中率高"
                        ));
                    }
                    r if r <= 20000 => {
                        reasons.push(format!(
                            "对称 NAT 端口范围约 {r} 个端口 ⇒ 预测命中率一般，靠穷举补齐"
                        ));
                    }
                    r => {
                        reasons.push(format!(
                            "对称 NAT 端口范围约 {r} 个端口 ⇒ 范围很大，纯预测几乎不可能命中，只能靠全局随机扫描（每轮 1200~1500 个端口）"
                        ));
                        advice.push(
                            "端口范围很大 ⇒ 直连可能要几分钟；期间 RDP 走中继，不影响可用性".into(),
                        );
                    }
                }
                if !profile.mapping_udp.is_empty() {
                    reasons.push(format!(
                        "已观测到公网 UDP 映射：{}",
                        profile.mapping_udp.join(", ")
                    ));
                }
                Expectation::DirectViaScanning
            }
        },
        MappingBehavior::Unknown => {
            reasons.push("未能判定 NAT 映射行为（探测可能未完成）".into());
            advice.push("重跑 irt diag；若始终未知，可用 netdiag/nat.js 交叉验证".into());
            Expectation::Unknown
        }
    };
    let ok = expectation == Expectation::Direct;

    if profile.transport == TransportKind::Iroh {
        reasons.push(
            "iroh 的打洞走「双方同时发包」，不需要 NAT 放行任意来源的入站 UDP ⇒ 地址依赖过滤不阻断直连"
                .into(),
        );
    } else {
        reasons.push(
            "rustp2p 的打洞同样走「双方同时发包」⇒ 地址依赖过滤不阻断直连；但辅助 socket 会增加映射端口的散布范围，端口预测会变难"
                .into(),
        );
    }

    match &profile.port_mapping {
        PortMappingStatus::Unsupported => {
            reasons.push(
                "UPnP / NAT-PMP / PCP 均不支持 ⇒ 不影响 EIM 下的打洞；但若映射随目标变化（非 EIM），\
                 就没有办法把映射固定下来，打洞无解"
                    .into(),
            );
            advice.push(
                "若本机 NAT 是对称型（映射随目标变化）：在路由器上手工把**本机 UDP 端口**\
                 固定转发出去 —— 端口固定后公网端口不再随目标变化，映射即变成 EIM，打洞就能成"
                    .into(),
            );
        }
        PortMappingStatus::Partial { upnp, nat_pmp, pcp } => {
            reasons.push(format!(
                "端口映射部分可用（UPnP={upnp} NAT-PMP={nat_pmp} PCP={pcp}）\
                 ⇒ 可以争取更快的首包"
            ));
            if profile.mapping == MappingBehavior::Symmetric {
                reasons.push(
                    "且本机 NAT 是对称型（映射随目标变化）⇒ 端口映射正是破解它的手段：\
                     固定端口后公网端点不再随目标变化，打洞可成"
                        .into(),
                );
                advice.push(
                    "启用路由器上的 UPnP / NAT-PMP / PCP（本工具会自动尝试申请端口映射）".into(),
                );
            }
        }
        PortMappingStatus::ProbeFailed(err) => {
            reasons.push(format!("端口映射探测失败：{err} ⇒ 不影响 EIM 下的打洞"));
        }
    }

    if !profile.udp_v4 {
        match (profile.transport, profile.udp_v6) {
            // iroh 的打洞候选只来自 QAD 的 global_v4 —— IPv4 不通就是没戏。
            (TransportKind::Iroh, _) => {
                reasons.push("IPv4 UDP 不可用 ⇒ 无法打洞".into());
                advice.push("检查本机防火墙是否拦截了出站 UDP".into());
            }
            // rustp2p 还能用 IPv6 的 STUN 观测拿到端口范围 ——
            // `public_port_range > 0` 就是「STUN 通了」的可靠信号
            // （rustp2p 的 NatInfo 在只观测到 IPv6 端口时，
            //  `public_ips` 与 `ipv6` 两个字段都会是空的）。
            (TransportKind::Rustp2p, false) if profile.port_range > 0 => {
                reasons.push(
                    "IPv4 未测到公网映射（STUN 可能只走 IPv6）⇒ 端口范围可能不准，但仍可打洞"
                        .into(),
                );
            }
            (TransportKind::Rustp2p, false) => {
                reasons.push("IPv4 与 IPv6 的 UDP 都不通 ⇒ 无法打洞".into());
                advice.push("检查本机防火墙是否拦截了出站 UDP".into());
            }
            (TransportKind::Rustp2p, true) => {
                // **只**IPv4 不通时要说清楚：这会让端口范围不准，
                // 但**不是**「无法打洞」—— IPv6 观测一样能给出端口范围。
                reasons.push(
                    "IPv4 未测到公网映射（STUN 可能只走 IPv6）⇒ 端口范围可能不准，但仍可打洞"
                        .into(),
                );
            }
        }
    }

    // 中继延迟高 ⇒ 走中继时 RDP 会明显卡。
    if let Some((url, latency)) = profile.relay_latencies.first() {
        let ms = latency.as_millis();
        if ms >= 150 {
            advice.push(format!(
                "中继延迟偏高（{url} {ms}ms）⇒ 走中继时 RDP 会卡；\
                 确保打洞成功走直连，或用 --relay 指向更近的中继"
            ));
        }
    }

    // IPv6：一旦本机有全局 IPv6，对端就能直接用 IPv6 连过来 ——
    // IPv6 根本不需要 NAT 遍历，是绕过对称 NAT 最省事的路子。
    match &profile.global_v6 {
        Some(v6) => advice.push(format!(
            "本机有全局 IPv6（{v6}）⇒ 对端可用 IPv6 直连，完全绕开 NAT 遍历；\
             保持默认 --publish relay 即可（IPv6 候选在已建立的连接上交换）"
        )),
        None => {
            if profile.udp_v4 {
                advice.push(
                    "本机无全局 IPv6 ⇒ 若对端有 IPv6 而本机没有，直连会因 \
                     NetworkUnreachable 直接失败；运营商光猫通常支持 IPv6，\
                     建议在光猫/路由器上开通并让内网拿到全局地址"
                        .into(),
                );
            }
        }
    }

    advice.push("管理员执行 irt server --install-firewall-rule 放行入站 UDP".into());
    // 这两条是 iroh 特有的（--publish / n0 中继），rustp2p 用自建 bootstrap。
    if profile.transport == TransportKind::Iroh {
        advice.push("server 保持默认 --publish relay".into());
        advice.push(
            "两端用**同一个** relay（如 --relay https://aps1-1.relay.n0.iroh.link./）：各自自动选容易选到不同家，多一跳中继转发会让 RTT 翻倍"
                .into(),
        );
    } else {
        advice.push(
            "两端用**同一个** bootstrap（--bootstrap）：自建中继既是发现入口也是转发节点，用不同的会让对端找不到你"
                .into(),
        );
    }
    advice.push("连接后看 client 输出是否出现「✅ 已切换到直连」".into());

    Verdict {
        expectation,
        ok,
        headline: expectation.headline().to_string(),
        reasons,
        advice,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::unstable_net_report::NetReport;

    fn report_with(mapping_varies: Option<bool>) -> NetReport {
        // Report 是 #[non_exhaustive]，外部 crate 不能用结构体字面量构造，
        // 但可以先 default 再逐字段赋值。
        let mut r = NetReport::default();
        r.mapping_varies_by_dest_ipv4 = mapping_varies;
        r.udp_v4 = true;
        r
    }

    fn profile(mapping_varies: Option<bool>) -> NatProfile {
        profile_from_report(
            &report_with(mapping_varies),
            PortMappingStatus::Unsupported,
        )
    }

    #[test]
    fn mapping_false_means_endpoint_independent() {
        assert_eq!(
            profile(Some(false)).mapping,
            MappingBehavior::EndpointIndependent
        );
    }

    #[test]
    fn mapping_true_means_symmetric() {
        assert_eq!(profile(Some(true)).mapping, MappingBehavior::Symmetric);
    }

    #[test]
    fn mapping_none_means_unknown() {
        assert_eq!(profile(None).mapping, MappingBehavior::Unknown);
    }

    #[test]
    fn ipv4_mapping_wins_over_ipv6() {
        // v4 是 EIM、v6 是对称 —— 合并判断会得出「对称」，
        // 但实际流量走 IPv4，结论应当是 EIM。
        let mut r = NetReport::default();
        r.mapping_varies_by_dest_ipv4 = Some(false);
        r.mapping_varies_by_dest_ipv6 = Some(true);
        let p = profile_from_report(&r, PortMappingStatus::Unsupported);
        assert_eq!(p.mapping, MappingBehavior::EndpointIndependent);
    }

    #[test]
    fn ipv6_is_used_when_ipv4_is_unknown() {
        let mut r = NetReport::default();
        r.mapping_varies_by_dest_ipv4 = None;
        r.mapping_varies_by_dest_ipv6 = Some(false);
        let p = profile_from_report(&r, PortMappingStatus::Unsupported);
        assert_eq!(p.mapping, MappingBehavior::EndpointIndependent);
    }

    #[test]
    fn verdict_is_ok_for_eim() {
        let v = verdict(&profile(Some(false)));
        assert!(v.ok, "EIM 下应判定可直连，实际: {:?}", v.reasons);
        assert!(v.headline.contains("✅"));
    }

    #[test]
    fn verdict_is_not_ok_for_symmetric() {
        let v = verdict(&profile(Some(true)));
        assert!(!v.ok, "对称 NAT 下不应判定可直连");
        assert!(v.headline.contains("❌"));
        assert!(
            v.advice.iter().any(|a| a.contains("端口") || a.contains("转发")),
            "应给出端口转发建议，实际: {:?}",
            v.advice
        );
    }

    #[test]
    fn verdict_is_not_ok_for_unknown() {
        let v = verdict(&profile(None));
        assert!(!v.ok);
    }

    #[test]
    fn unknown_is_not_reported_as_a_hard_failure() {
        let v = verdict(&profile(None));
        assert_eq!(v.expectation, Expectation::Unknown);
        assert!(
            v.headline.contains("未能判定"),
            "未知不应被渲染成硬失败，实际: {}",
            v.headline
        );
        assert!(
            !v.headline.contains("❌"),
            "未知不应带 ❌，实际: {}",
            v.headline
        );
    }

    #[test]
    fn expectation_headlines_are_distinct() {
        assert!(Expectation::Direct.headline().contains("✅"));
        assert!(Expectation::RelayOnly.headline().contains("❌"));
        assert!(Expectation::Unknown.headline().contains("⚠"));
    }

    #[test]
    fn verdict_always_explains_that_hole_punching_is_simultaneous() {
        for m in [Some(false), Some(true), None] {
            let v = verdict(&profile(m));
            assert!(
                v.reasons.iter().any(|r| r.contains("双方同时发包")),
                "结论里必须说明打洞是双方同时发包，实际: {:?}",
                v.reasons
            );
        }
    }

    #[test]
    fn verdict_mentions_udp_v4_failure() {
        let mut p = profile(Some(false));
        p.udp_v4 = false;
        let v = verdict(&p);
        assert!(v.reasons.iter().any(|r| r.contains("IPv4 UDP 不可用")));
    }

    #[test]
    fn home_relay_defaults_to_none() {
        assert!(profile(Some(false)).home_relay.is_none());
    }

    #[test]
    fn high_relay_latency_is_flagged() {
        let mut p = profile(Some(false));
        p.relay_latencies = vec![(
            "https://euc1-1.relay.n0.iroh.link.".parse().unwrap(),
            Duration::from_millis(240),
        )];
        let v = verdict(&p);
        assert!(
            v.advice.iter().any(|a| a.contains("中继延迟偏高")),
            "中继延迟高时应给出提醒，实际: {:?}",
            v.advice
        );
    }

    #[test]
    fn low_relay_latency_is_not_flagged() {
        let mut p = profile(Some(false));
        p.relay_latencies = vec![(
            "https://aps1-1.relay.n0.iroh.link.".parse().unwrap(),
            Duration::from_millis(40),
        )];
        let v = verdict(&p);
        assert!(
            !v.advice.iter().any(|a| a.contains("中继延迟偏高")),
            "中继延迟低时不应提醒，实际: {:?}",
            v.advice
        );
    }

    #[test]
    fn labels_are_descriptive() {
        assert!(MappingBehavior::EndpointIndependent.label().contains("EIM"));
        assert!(MappingBehavior::Symmetric.label().contains("对称"));
        assert_eq!(MappingBehavior::Unknown.label(), "未知");
    }

    // ------------------------------------------------------------------
    // rustp2p 的 NAT 画像（v0.3）
    // ------------------------------------------------------------------

    /// 造一个 rustp2p 的 NAT 观测结果。
    ///
    /// `NatType` 没有被 rustp2p-quic re-export，所以用 JSON 反序列化构造 ——
    /// 免得为了测试多引一个依赖。
    fn rustp2p_nat_info(
        nat_type: &str,
        port_range: u16,
        mapping_udp: &[&str],
    ) -> rustp2p_quic::NatInfo {
        let mapping: Vec<String> = mapping_udp
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect();
        let json = format!(
            r#"{{"nat_type":"{nat_type}","public_ips":["171.37.192.67"],
                "public_udp_ports":[40000],"mapping_tcp_addr":[],
                "mapping_udp_addr":[{}],"public_port_range":{port_range},
                "local_ipv4":"192.168.1.2","local_ipv4s":[],"ipv6":null,
                "local_udp_ports":[50000],"local_tcp_port":0,
                "public_tcp_port":0}}"#,
            mapping.join(",")
        );
        serde_json::from_str(&json).expect("NatInfo JSON 应能反序列化")
    }

    #[test]
    fn rustp2p_profile_reads_type_and_port_range() {
        let info = rustp2p_nat_info("Symmetric", 30000, &["171.37.192.67:40000"]);
        let profile = profile_from_rustp2p(&info, PortMappingStatus::Unsupported);
        assert_eq!(profile.mapping, MappingBehavior::Symmetric);
        assert_eq!(profile.transport, TransportKind::Rustp2p);
        assert_eq!(profile.port_range, 30000);
        assert_eq!(profile.mapping_udp, vec!["171.37.192.67:40000".to_string()]);
        assert!(profile.global_v4.is_some());
    }

    #[test]
    fn cone_nat_maps_to_endpoint_independent() {
        let info = rustp2p_nat_info("Cone", 0, &[]);
        let profile = profile_from_rustp2p(&info, PortMappingStatus::Unsupported);
        assert_eq!(profile.mapping, MappingBehavior::EndpointIndependent);
    }

    #[test]
    fn symmetric_nat_with_rustp2p_expects_scanning() {
        let info = rustp2p_nat_info("Symmetric", 30000, &["171.37.192.67:40000"]);
        let profile = profile_from_rustp2p(&info, PortMappingStatus::Unsupported);
        let v = verdict(&profile);
        assert_eq!(
            v.expectation,
            Expectation::DirectViaScanning,
            "rustp2p 面对对称 NAT 应当判「可破」而不是「无望」"
        );
        assert!(
            v.reasons.iter().any(|r| r.contains("端口范围")),
            "判定理由里必须出现「端口范围」，实际: {:?}",
            v.reasons
        );
    }

    #[test]
    fn symmetric_nat_with_iroh_expects_relay_only() {
        let mut profile = profile_from_rustp2p(
            &rustp2p_nat_info("Symmetric", 30000, &[]),
            PortMappingStatus::Unsupported,
        );
        // 同一个 NAT，换成 iroh 后端 —— 结论必须相反。
        profile.transport = TransportKind::Iroh;
        let v = verdict(&profile);
        assert_eq!(v.expectation, Expectation::RelayOnly);
        assert!(
            v.advice.iter().any(|a| a.contains("rustp2p")),
            "iroh 判无望时应建议改用 rustp2p，实际: {:?}",
            v.advice
        );
    }

    #[test]
    fn unknown_port_range_is_called_out() {
        let info = rustp2p_nat_info("Symmetric", 0, &[]);
        let profile = profile_from_rustp2p(&info, PortMappingStatus::Unsupported);
        let v = verdict(&profile);
        assert_eq!(v.expectation, Expectation::DirectViaScanning);
        assert!(
            v.reasons.iter().any(|r| r.contains("未测得端口范围")),
            "端口范围未知时必须说明，实际: {:?}",
            v.reasons
        );
    }

    #[test]
    fn large_port_range_warns_about_slow_punching() {
        let info = rustp2p_nat_info("Symmetric", 60000, &[]);
        let profile = profile_from_rustp2p(&info, PortMappingStatus::Unsupported);
        let v = verdict(&profile);
        assert!(
            v.advice.iter().any(|a| a.contains("几分钟")),
            "端口范围很大时应提示直连耗时，实际: {:?}",
            v.advice
        );
    }
}
