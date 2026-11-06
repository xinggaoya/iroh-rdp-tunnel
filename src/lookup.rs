//! 查询对端在 n0 公共发现服务上**实际公布**出来的地址。
//!
//! 这一层信息直接决定「客户端到底能不能建连」，是排障里最关键、也最容易被忽略的一环：
//!
//! | 对端公布的记录 | 客户端能走的路 | 后果 |
//! |---|---|---|
//! | 含 relay URL | 中继路径（+ 可能打洞） | ✅ 一定能连上 |
//! | 只有 IP | 只能直连 | ⚠ 若 NAT 是地址依赖过滤，首包被丢弃 → 必然超时 |
//! | 什么都没有 | 无 | ❌ 连不上 |
//!
//! 注意「记录里同时有 relay 和 IP」与「只有 relay」的差别：前者是正常的（iroh 内部
//! 靠 relay 做会合、再打洞），后者是 `relay-only` 发布策略的正常结果，
//! 而**只有 IP 没有 relay** 才是危险信号 —— 客户端会被困在直连上。

use anyhow::Context as _;
use iroh::{
    EndpointId, TransportAddr,
    dns::{DnsResolver, N0_DNS_ENDPOINT_ORIGIN_PROD},
};
use serde::Serialize;

/// 对端公布出来的地址集合。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerRecord {
    /// 对端公布的中继 URL。
    pub relays: Vec<String>,
    /// 对端公布的 IP 端点。
    pub ips: Vec<String>,
}

impl PeerRecord {
    /// 从发现服务返回的地址列表构造。
    pub fn from_addrs<'a>(addrs: impl Iterator<Item = &'a TransportAddr>) -> Self {
        let mut this = Self::default();
        for addr in addrs {
            match addr {
                TransportAddr::Relay(url) => {
                    let url = url.to_string();
                    if !this.relays.contains(&url) {
                        this.relays.push(url);
                    }
                }
                TransportAddr::Ip(sa) => {
                    let sa = sa.to_string();
                    if !this.ips.contains(&sa) {
                        this.ips.push(sa);
                    }
                }
                // TransportAddr 是 #[non_exhaustive]，未来可能新增变体。
                _ => {}
            }
        }
        this
    }

    /// 客户端能否建立中继路径。
    ///
    /// 有 relay URL 就一定能连上 —— 中继路径不受本地 NAT 过滤行为影响。
    pub fn can_reach_via_relay(&self) -> bool {
        !self.relays.is_empty()
    }

    /// 客户端是否会尝试直连。
    pub fn can_try_direct(&self) -> bool {
        !self.ips.is_empty()
    }

    /// 给出判定。
    pub fn verdict(&self) -> LookupVerdict {
        let mut reasons = Vec::new();
        let mut advice = Vec::new();

        let (ok, headline) = if self.can_reach_via_relay() {
            reasons.push("记录里含 relay URL：客户端可以经中继建连，必然可用".to_string());
            if self.can_try_direct() {
                reasons.push("同时公布了 IP：客户端会先尝试直连、打洞失败再回落中继".to_string());
                advice.push("连接后看 client 是否出现「✅ 已切换到直连」".to_string());
            } else {
                reasons.push(
                    "只公布了 relay URL（relay-only 策略）：直连需要双方同时发包打洞，\
                     成功前流量走中继"
                        .to_string(),
                );
                advice.push("中继延迟高？用 --relay 指定更近的中继".to_string());
            }
            (true, "✅ 客户端能连上")
        } else if self.can_try_direct() {
            reasons.push(
                "记录里**没有 relay URL**，只有 IP：客户端无法建立中继路径，只能直连".to_string(),
            );
            reasons.push(
                "若对端 NAT 是地址依赖过滤（家宽光猫常见），客户端首包会被丢弃 → 30 秒超时"
                    .to_string(),
            );
            advice.push("让对端改用 relay-only 发布策略：irt server --publish relay".to_string());
            advice.push(
                "或直接用 `irt diag --lookup <id>` 复查，确认记录里已出现 relay=".to_string(),
            );
            (false, "❌ 客户端很可能连不上（只有直连路径）")
        } else {
            reasons.push("查到的记录里既没有 relay URL 也没有 IP".to_string());
            reasons.push("对端可能没在发布、或 endpoint id 抄错了".to_string());
            advice.push("核对 endpoint id；确认对端 `irt server` 正在运行".to_string());
            (false, "❌ 查不到对端的任何地址")
        };

        LookupVerdict {
            ok,
            headline: headline.to_string(),
            reasons,
            advice,
        }
    }
}

/// 判定结果。
#[derive(Debug, Clone)]
pub struct LookupVerdict {
    /// 客户端能否连上。
    pub ok: bool,
    /// 一句话结论。
    pub headline: String,
    /// 依据。
    pub reasons: Vec<String>,
    /// 建议动作。
    pub advice: Vec<String>,
}

/// JSON 输出结构。
#[derive(Debug, Clone, Serialize)]
pub struct LookupReportJson {
    /// 查询的 endpoint id。
    pub endpoint_id: String,
    /// 对端公布的中继 URL。
    pub relays: Vec<String>,
    /// 对端公布的 IP 端点。
    pub ips: Vec<String>,
    /// 客户端能否经中继建连。
    pub can_reach_via_relay: bool,
    /// 客户端是否会尝试直连。
    pub can_try_direct: bool,
    /// 结论标题。
    pub headline: String,
    /// 依据。
    pub reasons: Vec<String>,
    /// 建议。
    pub advice: Vec<String>,
}

/// 查询结果 + 判定的组合。
#[derive(Debug, Clone)]
pub struct LookupReport {
    /// 被查询的 endpoint id。
    pub endpoint_id: EndpointId,
    /// 查到的地址集合。
    pub record: PeerRecord,
    /// 判定。
    pub verdict: LookupVerdict,
}

impl LookupReport {
    /// 转成可 JSON 序列化的结构。
    pub fn to_json(&self) -> LookupReportJson {
        LookupReportJson {
            endpoint_id: self.endpoint_id.to_string(),
            relays: self.record.relays.clone(),
            ips: self.record.ips.clone(),
            can_reach_via_relay: self.record.can_reach_via_relay(),
            can_try_direct: self.record.can_try_direct(),
            headline: self.verdict.headline.clone(),
            reasons: self.verdict.reasons.clone(),
            advice: self.verdict.advice.clone(),
        }
    }
}

/// 渲染成人类可读的文本。
pub fn render(report: &LookupReport) -> String {
    let rec = &report.record;
    let v = &report.verdict;
    let mut out = String::new();

    out.push_str("=========================================================\n");
    out.push_str(" iroh-rdp-tunnel 对端公布地址查询\n");
    out.push_str("=========================================================\n");
    out.push_str(&format!(" endpoint id   : {}\n", report.endpoint_id));

    out.push_str(" 公布的中继     : ");
    if rec.relays.is_empty() {
        out.push_str("（无 —— 客户端无法建立中继路径）\n");
    } else {
        out.push('\n');
        for r in &rec.relays {
            out.push_str(&format!("                 {r}\n"));
        }
    }

    out.push_str(" 公布的 IP     : ");
    if rec.ips.is_empty() {
        out.push_str("（无）\n");
    } else {
        out.push('\n');
        for ip in &rec.ips {
            out.push_str(&format!("                 {ip}\n"));
        }
    }

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
pub fn render_json(report: &LookupReport) -> String {
    match serde_json::to_string_pretty(&report.to_json()) {
        Ok(s) => s,
        Err(e) => format!("{{\"error\":\"{e}\"}}"),
    }
}

/// 向 n0 公共 DNS 查询对端公布的地址。
///
/// 用的是与 iroh 客户端**完全相同**的解析路径（`_iroh.<z32>.dns.iroh.link` 的
/// TXT 记录），因此查到的就是客户端会拿到的东西。
pub async fn lookup(endpoint_id: EndpointId) -> anyhow::Result<LookupReport> {
    let resolver = DnsResolver::new();
    let info = resolver
        .lookup_endpoint_by_id(&endpoint_id, N0_DNS_ENDPOINT_ORIGIN_PROD)
        .await
        .context("查询 n0 公共 DNS 失败（网络不通或记录不存在）")?;
    let record = PeerRecord::from_addrs(info.addrs());
    let verdict = record.verdict();
    Ok(LookupReport {
        endpoint_id,
        record,
        verdict,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::{RelayUrl, SecretKey};
    use std::net::SocketAddr;

    /// 随机生成一个合法的 endpoint id（ed25519 公钥必须落在曲线上）。
    fn any_endpoint_id() -> EndpointId {
        SecretKey::generate().public()
    }

    fn relay(url: &str) -> TransportAddr {
        TransportAddr::Relay(url.parse::<RelayUrl>().unwrap())
    }

    fn ip(addr: &str) -> TransportAddr {
        TransportAddr::Ip(addr.parse::<SocketAddr>().unwrap())
    }

    #[test]
    fn splits_relay_and_ip() {
        let addrs = [
            relay("https://aps1-1.relay.n0.iroh.link./"),
            ip("171.37.192.67:34622"),
        ];
        let rec = PeerRecord::from_addrs(addrs.iter());
        assert_eq!(rec.relays, ["https://aps1-1.relay.n0.iroh.link./"]);
        assert_eq!(rec.ips, ["171.37.192.67:34622"]);
    }

    #[test]
    fn dedupes_repeated_addresses() {
        let addrs = [
            relay("https://aps1-1.relay.n0.iroh.link./"),
            relay("https://aps1-1.relay.n0.iroh.link./"),
        ];
        let rec = PeerRecord::from_addrs(addrs.iter());
        assert_eq!(rec.relays.len(), 1);
    }

    #[test]
    fn relay_only_is_acceptable() {
        let addrs = [relay("https://aps1-1.relay.n0.iroh.link./")];
        let rec = PeerRecord::from_addrs(addrs.iter());
        let v = rec.verdict();
        assert!(v.ok, "relay-only 的记录必须判为可连：{}", v.headline);
        assert!(rec.can_reach_via_relay());
        assert!(!rec.can_try_direct());
    }

    #[test]
    fn ip_only_is_rejected() {
        // 这正是本次故障的形态：客户端拿不到 relay，只能直连 → 被 NAT 过滤丢弃。
        let addrs = [ip("171.37.192.67:33946")];
        let rec = PeerRecord::from_addrs(addrs.iter());
        let v = rec.verdict();
        assert!(!v.ok, "只有 IP 的记录必须判为不可连：{}", v.headline);
        assert!(!rec.can_reach_via_relay());
        assert!(rec.can_try_direct());
        assert!(
            v.advice.iter().any(|a| a.contains("--publish relay")),
            "必须给出改发布策略的建议，实际: {:?}",
            v.advice
        );
    }

    #[test]
    fn empty_record_is_rejected() {
        let rec = PeerRecord::default();
        let v = rec.verdict();
        assert!(!v.ok);
        assert!(v.headline.contains("查不到"));
    }

    #[test]
    fn relay_plus_ip_is_acceptable() {
        let addrs = [
            relay("https://aps1-1.relay.n0.iroh.link./"),
            ip("171.37.192.67:34622"),
        ];
        let rec = PeerRecord::from_addrs(addrs.iter());
        let v = rec.verdict();
        assert!(v.ok, "{}", v.headline);
    }

    #[test]
    fn render_shows_the_missing_relay_loudly() {
        let id = any_endpoint_id();
        let rec = PeerRecord::from_addrs([ip("171.37.192.67:33946")].iter());
        let verdict = rec.verdict();
        let text = render(&LookupReport {
            endpoint_id: id,
            record: rec,
            verdict,
        });
        assert!(text.contains("（无 —— 客户端无法建立中继路径）"), "实际:\n{text}");
        assert!(text.contains("❌"), "实际:\n{text}");
    }

    #[test]
    fn json_round_trips() {
        let id = any_endpoint_id();
        let rec = PeerRecord::from_addrs([relay("https://aps1-1.relay.n0.iroh.link./")].iter());
        let verdict = rec.verdict();
        let json = render_json(&LookupReport {
            endpoint_id: id,
            record: rec,
            verdict,
        });
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON 必须可解析");
        assert_eq!(parsed["can_reach_via_relay"], true);
        assert_eq!(parsed["can_try_direct"], false);
        assert_eq!(parsed["relays"][0], "https://aps1-1.relay.n0.iroh.link./");
    }
}
