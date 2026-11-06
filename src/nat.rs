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

use crate::portmap::PortMappingStatus;

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
    }
}

/// 直连预期。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expectation {
    /// 预期能 P2P 直连。
    Direct,
    /// 预期只能走中继。
    RelayOnly,
    /// 未能判定（探测未完成或映射行为未知）。
    Unknown,
}

impl Expectation {
    /// 一句话结论。
    pub fn headline(self) -> &'static str {
        match self {
            Expectation::Direct => "✅ 具备 P2P 直连条件",
            Expectation::RelayOnly => "❌ 直连条件不足，预计只能走中继",
            Expectation::Unknown => "⚠️ 未能判定 —— 探测可能未完成，请重跑 irt diag",
        }
    }

    /// 机器可读的名字。
    pub fn as_str(self) -> &'static str {
        match self {
            Expectation::Direct => "direct",
            Expectation::RelayOnly => "relay-only",
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
        MappingBehavior::Symmetric => {
            reasons.push(
                "映射随目标变化（对称 NAT）⇒ 通告出去的公网端点对不上号，打洞必败".into(),
            );
            advice.push(
                "只能走中继；或在光猫上手工把内网 UDP 端口固定转发出去（消除对称 NAT 的影响）"
                    .into(),
            );
            Expectation::RelayOnly
        }
        MappingBehavior::Unknown => {
            reasons.push("未能判定 NAT 映射行为（探测可能未完成）".into());
            advice.push("重跑 irt diag；若始终未知，可用 netdiag/nat.js 交叉验证".into());
            Expectation::Unknown
        }
    };
    let ok = expectation == Expectation::Direct;

    reasons.push(
        "iroh 的打洞走「双方同时发包」，不需要 NAT 放行任意来源的入站 UDP ⇒ 地址依赖过滤不阻断直连"
            .into(),
    );

    match &profile.port_mapping {
        PortMappingStatus::Unsupported => {
            reasons.push(
                "UPnP / NAT-PMP / PCP 均不支持 ⇒ 不影响打洞（EIM 下内端口固定即端点稳定），仅损失「首包更快」的机会"
                    .into(),
            );
        }
        PortMappingStatus::Partial { upnp, nat_pmp, pcp } => {
            reasons.push(format!(
                "端口映射部分可用（UPnP={upnp} NAT-PMP={nat_pmp} PCP={pcp}）⇒ 可以争取更快的首包"
            ));
        }
        PortMappingStatus::ProbeFailed(err) => {
            reasons.push(format!("端口映射探测失败：{err} ⇒ 不影响打洞"));
        }
    }

    if !profile.udp_v4 {
        reasons.push("IPv4 UDP 不可用 ⇒ 无法打洞".into());
        advice.push("检查本机防火墙是否拦截了出站 UDP".into());
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

    advice.push("server 保持默认 --publish relay".into());
    advice.push("管理员执行 irt server --install-firewall-rule 放行入站 UDP".into());
    advice.push(
        "两端用**同一个** relay（如 --relay https://aps1-1.relay.n0.iroh.link./）：\
         各自自动选容易选到不同家，多一跳中继转发会让 RTT 翻倍"
            .into(),
    );
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
}
