//! 端口映射（UPnP / NAT-PMP / PCP）可用性探测。
//!
//! 这三种协议都是**可选**的：没有它们，打洞照样能成（EIM 映射下内端口固定，
//! 公网端点就稳定）。它们的价值只是让首包更快一点。
//!
//! 探测失败必须降级为「未知」而不是让体检整体失败 —— 网络环境千差万别。

/// 端口映射状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortMappingStatus {
    /// 三种协议都不支持。
    Unsupported,
    /// 部分可用。
    Partial {
        /// UPnP 可用。
        upnp: bool,
        /// NAT-PMP 可用。
        nat_pmp: bool,
        /// PCP 可用。
        pcp: bool,
    },
    /// 探测失败。
    ProbeFailed(String),
}

impl PortMappingStatus {
    /// 是否三种协议全都不支持。
    pub fn is_unsupported(&self) -> bool {
        matches!(self, PortMappingStatus::Unsupported)
    }

    /// 一行摘要。
    pub fn summary(&self) -> String {
        match self {
            PortMappingStatus::Unsupported => "UPnP ❌  NAT-PMP ❌  PCP ❌（不支持）".to_string(),
            PortMappingStatus::Partial {
                upnp,
                nat_pmp,
                pcp,
            } => format!(
                "UPnP {}  NAT-PMP {}  PCP {}",
                mark(*upnp),
                mark(*nat_pmp),
                mark(*pcp)
            ),
            PortMappingStatus::ProbeFailed(err) => format!("探测失败：{err}"),
        }
    }
}

/// 可用 → ✅，不可用 → ❌。
fn mark(ok: bool) -> &'static str {
    if ok {
        "✅"
    } else {
        "❌"
    }
}

/// 跑一次端口映射协议探测。
pub async fn probe() -> PortMappingStatus {
    let client = portmapper::Client::new(portmapper::Config::default());
    // probe() 返回的是 oneshot 接收器：先等结果，再看里面的 Result。
    match client.probe().await {
        Ok(Ok(out)) => {
            if !out.upnp && !out.nat_pmp && !out.pcp {
                PortMappingStatus::Unsupported
            } else {
                PortMappingStatus::Partial {
                    upnp: out.upnp,
                    nat_pmp: out.nat_pmp,
                    pcp: out.pcp,
                }
            }
        }
        Ok(Err(e)) => PortMappingStatus::ProbeFailed(e.to_string()),
        Err(_) => PortMappingStatus::ProbeFailed("探测通道提前关闭".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_summary_lists_all_three_protocols() {
        let s = PortMappingStatus::Unsupported.summary();
        assert!(s.contains("UPnP"));
        assert!(s.contains("NAT-PMP"));
        assert!(s.contains("PCP"));
        assert!(s.contains('❌'));
    }

    #[test]
    fn partial_summary_marks_each_protocol() {
        let s = PortMappingStatus::Partial {
            upnp: true,
            nat_pmp: false,
            pcp: false,
        }
        .summary();
        assert!(s.contains("UPnP ✅"));
        assert!(s.contains("NAT-PMP ❌"));
        assert!(s.contains("PCP ❌"));
    }

    #[test]
    fn probe_failure_is_reported_not_panicked() {
        let s = PortMappingStatus::ProbeFailed("boom".into()).summary();
        assert!(s.contains("boom"));
    }

    #[test]
    fn is_unsupported_only_for_all_false() {
        assert!(PortMappingStatus::Unsupported.is_unsupported());
        assert!(!PortMappingStatus::Partial {
            upnp: true,
            nat_pmp: false,
            pcp: false
        }
        .is_unsupported());
    }
}
