//! 网络体检报告的组装与渲染。

use serde::Serialize;

use crate::nat::{NatProfile, Verdict};

/// NAT 过滤行为 —— iroh 的 net report **测不了**，如实标注而不是编造。
///
/// 这不影响结论：iroh 的打洞走「双方同时发包」，本来就不需要 NAT 放行任意来源的入站。
pub const FILTERING_NOT_MEASURED: &str =
    "未测量（iroh 无法直接探测；严格验证请用外部 STUN 工具）";

/// 体检报告。
#[derive(Debug, Clone)]
pub struct DiagReport {
    /// NAT 画像。
    pub profile: NatProfile,
    /// 判定结论。
    pub verdict: Verdict,
}

/// JSON 输出结构。
#[derive(Debug, Clone, Serialize)]
pub struct DiagReportJson {
    /// 公网 IPv4 端点。
    pub global_v4: Option<String>,
    /// 公网 IPv6 端点。
    pub global_v6: Option<String>,
    /// 映射行为标签。
    pub mapping: String,
    /// IPv4 UDP 是否可用。
    pub udp_v4: bool,
    /// IPv6 UDP 是否可用。
    pub udp_v6: bool,
    /// 疑似运营商门户。
    pub captive_portal: Option<bool>,
    /// 延迟最低的中继（探测所得）。
    pub preferred_relay: Option<String>,
    /// 实际选定的 home relay。
    pub home_relay: Option<String>,
    /// 各中继延迟。
    pub relay_latencies: Vec<RelayLatencyJson>,
    /// 端口映射状态。
    pub port_mapping: String,
    /// NAT 过滤行为 —— iroh 测不了，如实标注。
    pub filtering_behavior: String,
    /// 是否预期能 P2P 直连。
    pub p2p_direct_expected: bool,
    /// 结论标题。
    pub headline: String,
    /// 依据。
    pub reasons: Vec<String>,
    /// 建议。
    pub advice: Vec<String>,
}

/// 单个中继的延迟。
#[derive(Debug, Clone, Serialize)]
pub struct RelayLatencyJson {
    /// 中继 URL。
    pub relay: String,
    /// 延迟（毫秒）。
    pub latency_ms: u128,
}

impl DiagReport {
    /// 转成可 JSON 序列化的结构。
    pub fn to_json(&self) -> DiagReportJson {
        DiagReportJson {
            global_v4: self.profile.global_v4.map(|a| a.to_string()),
            global_v6: self.profile.global_v6.map(|a| a.to_string()),
            mapping: self.profile.mapping.label().to_string(),
            udp_v4: self.profile.udp_v4,
            udp_v6: self.profile.udp_v6,
            captive_portal: self.profile.captive_portal,
            preferred_relay: self
                .profile
                .preferred_relay
                .as_ref()
                .map(|u| u.to_string()),
            home_relay: self.profile.home_relay.as_ref().map(|u| u.to_string()),
            relay_latencies: self
                .profile
                .relay_latencies
                .iter()
                .map(|(url, d)| RelayLatencyJson {
                    relay: url.to_string(),
                    latency_ms: d.as_millis(),
                })
                .collect(),
            port_mapping: self.profile.port_mapping.summary(),
            filtering_behavior: FILTERING_NOT_MEASURED.to_string(),
            p2p_direct_expected: self.verdict.ok,
            headline: self.verdict.headline.clone(),
            reasons: self.verdict.reasons.clone(),
            advice: self.verdict.advice.clone(),
        }
    }
}

/// 渲染成人类可读的文本。
pub fn render(report: &DiagReport) -> String {
    let p = &report.profile;
    let v = &report.verdict;
    let mut out = String::new();

    out.push_str("=========================================================\n");
    out.push_str(" iroh-rdp-tunnel 网络体检\n");
    out.push_str("=========================================================\n");

    out.push_str(&format!(
        " 公网 IPv4 端点   : {}\n",
        p.global_v4
            .map(|a| a.to_string())
            .unwrap_or_else(|| "（未探测到）".to_string())
    ));
    out.push_str(&format!(
        " 公网 IPv6 端点   : {}\n",
        p.global_v6
            .map(|a| a.to_string())
            .unwrap_or_else(|| "（无全局地址）".to_string())
    ));
    out.push_str(&format!(
        " NAT 映射行为     : {}  {}\n",
        p.mapping.label(),
        match p.mapping {
            crate::nat::MappingBehavior::EndpointIndependent => "✅ 公网端点稳定，可通告",
            crate::nat::MappingBehavior::Symmetric => "❌ 端点对不上号，直连会失败",
            crate::nat::MappingBehavior::Unknown => "⚠ 未判定",
        }
    ));
    // 过滤行为 iroh 测不了 —— 如实标注，不编造。
    out.push_str(&format!(" NAT 过滤行为     : {FILTERING_NOT_MEASURED}\n"));
    out.push_str("                   → 但这不阻断直连：iroh 的打洞走「双方同时发包」\n");
    out.push_str(&format!(
        " UDP 可用         : IPv4 {}   IPv6 {}\n",
        if p.udp_v4 { "✅" } else { "❌" },
        if p.udp_v6 { "✅" } else { "❌" }
    ));
    out.push_str(&format!(" 端口映射         : {}\n", p.port_mapping.summary()));
    if p.port_mapping.is_unsupported() {
        out.push_str(
            "                   → 不影响：EIM 映射下内端口固定即端点稳定，打洞不依赖端口映射\n",
        );
    }
    if let Some(cp) = p.captive_portal {
        if cp {
            out.push_str(" 运营商门户       : ⚠ 疑似存在，HTTP 出口可能被劫持\n");
        }
    }

    out.push('\n');
    out.push_str(&format!(
        " 实际 home relay : {}\n",
        match &p.home_relay {
            Some(u) => u.to_string(),
            None => "（未确定）".to_string(),
        }
    ));
    out.push_str(&format!(
        " 探测最快中继     : {}\n",
        match &p.preferred_relay {
            Some(u) => u.to_string(),
            None => "（未确定）".to_string(),
        }
    ));
    for (url, latency) in &p.relay_latencies {
        out.push_str(&format!("                     {url}  {}ms\n", latency.as_millis()));
    }
    out.push_str("                   （探测有 5 秒总超时，未列出的中继不代表不可达）\n");

    out.push('\n');
    out.push_str(&format!(" 判定: {}\n", v.headline));
    for r in &v.reasons {
        out.push_str(&format!("   · {r}\n"));
    }
    out.push_str(" 建议:\n");
    for (i, a) in v.advice.iter().enumerate() {
        out.push_str(&format!("   {}. {a}\n", i + 1));
    }
    out.push_str("=========================================================\n");
    out
}

/// 渲染成 JSON。
pub fn render_json(report: &DiagReport) -> String {
    match serde_json::to_string_pretty(&report.to_json()) {
        Ok(s) => s,
        Err(e) => format!("{{\"error\":\"{e}\"}}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::{MappingBehavior, profile_from_report, verdict};
    use crate::portmap::PortMappingStatus;
    use iroh::unstable_net_report::NetReport;

    fn sample_report() -> DiagReport {
        let mut r = NetReport::default();
        r.mapping_varies_by_dest_ipv4 = Some(false);
        r.udp_v4 = true;
        r.global_v4 = Some("171.37.192.67:34622".parse().unwrap());
        let profile = profile_from_report(&r, PortMappingStatus::Unsupported);
        let verdict = verdict(&profile);
        DiagReport { profile, verdict }
    }

    #[test]
    fn render_states_that_filtering_behavior_is_not_measured() {
        let text = render(&sample_report());
        assert!(
            text.contains("未测量"),
            "报告必须如实标注过滤行为未测量，实际:\n{text}"
        );
    }

    #[test]
    fn json_also_states_that_filtering_behavior_is_not_measured() {
        let json = render_json(&sample_report());
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let v = parsed["filtering_behavior"].as_str().unwrap();
        assert!(v.contains("未测量"), "JSON 也必须如实标注，实际: {v}");
    }

    #[test]
    fn render_contains_the_public_endpoint() {
        let text = render(&sample_report());
        assert!(text.contains("171.37.192.67:34622"), "实际:\n{text}");
    }

    #[test]
    fn render_contains_mapping_and_verdict() {
        let text = render(&sample_report());
        assert!(text.contains("EIM"), "实际:\n{text}");
        assert!(text.contains("具备 P2P 直连条件"), "实际:\n{text}");
    }

    #[test]
    fn render_mentions_port_mapping_is_not_needed() {
        let text = render(&sample_report());
        assert!(text.contains("不依赖端口映射"), "实际:\n{text}");
    }

    #[test]
    fn render_lists_advice() {
        let text = render(&sample_report());
        assert!(text.contains("--install-firewall-rule"), "实际:\n{text}");
        assert!(text.contains("已切换到直连"), "实际:\n{text}");
    }

    #[test]
    fn json_output_is_valid_and_round_trips() {
        let json = render_json(&sample_report());
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("JSON 必须可解析");
        assert_eq!(parsed["global_v4"], "171.37.192.67:34622");
        assert_eq!(parsed["p2p_direct_expected"], true);
        assert!(parsed["mapping"].as_str().unwrap().contains("EIM"));
    }

    #[test]
    fn json_reports_symmetric_as_not_direct() {
        let mut r = NetReport::default();
        r.mapping_varies_by_dest_ipv4 = Some(true);
        let profile = profile_from_report(&r, PortMappingStatus::Unsupported);
        assert_eq!(profile.mapping, MappingBehavior::Symmetric);
        let report = DiagReport {
            verdict: verdict(&profile),
            profile,
        };
        let parsed: serde_json::Value = serde_json::from_str(&render_json(&report)).unwrap();
        assert_eq!(parsed["p2p_direct_expected"], false);
    }
}
