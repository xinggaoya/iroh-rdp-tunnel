//! 传输层抽象：把「怎么把字节从 A 机送到 B 机」从 RDP 隧道逻辑里剥离出来。
//!
//! # 为什么需要这一层
//!
//! v0.2 只用 iroh，而 iroh 的打洞候选**只**来自 QAD（中继观测到的端点）。
//! 在**对称 NAT**（映射随目标变化）下，中继观测到的端口与对端真实可达端口对不上号，
//! 于是打洞**永远**打不通 —— 这是架构性限制，不是配置问题。
//!
//! v0.3 引入 rustp2p-quic 作为第二个后端：它用「端口预测 + 全局随机扫描」
//! 正面解决对称 NAT。两个后端的连接建立方式、流语义、路径事件都不一样，
//! 所以这里定义一层**最小**的统一抽象，让上层的 RDP 桥接逻辑一行都不用改。
//!
//! # 抽象边界
//!
//! 刻意**不**抽象的东西：
//!
//! - 不抽象「连接」对象。两个后端的连接模型完全不同：
//!   iroh 是一条 QUIC 连接上可以开多条流；rustp2p 是**流即连接**
//!   （`open_bi` 直接给流，没有独立的连接句柄）。
//! - 不抽象重连策略。iroh 后端保留 v0.2 的 [`crate::connmgr`] 常驻连接 + 指数退避；
//!   rustp2p 后端自己管连接复用。
//!
//! 统一到**「开一条字节流」**这一层就够用了 —— RDP 隧道只关心字节流。

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::broadcast;

use crate::pathinfo::{PathInfo, PathKind};

pub mod iroh;
pub mod rustp2p;

/// iroh 的 endpoint id（公钥指纹）。
///
/// 注意必须写成 `::iroh::EndpointId` —— 本模块下有 `pub mod iroh`，
/// 不加 `::` 会解析到子模块而不是外部 crate。
pub type IrohEndpointId = ::iroh::EndpointId;

/// 传输后端种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// iroh（QUIC + n0 中继 + pkarr 发现）。
    Iroh,
    /// rustp2p-quic（QUIC + 自建中继 + 端口预测打洞）。
    Rustp2p,
}

impl TransportKind {
    /// 中文标签，用于 CLI 输出。
    pub fn label(self) -> &'static str {
        match self {
            TransportKind::Iroh => "iroh",
            TransportKind::Rustp2p => "rustp2p",
        }
    }

    /// 从 CLI 传入的字符串解析。
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "iroh" => Ok(TransportKind::Iroh),
            "rustp2p" | "r2p" => Ok(TransportKind::Rustp2p),
            other => anyhow::bail!("未知的传输后端: {other}（可选: iroh / rustp2p）"),
        }
    }
}

/// 对端标识。
///
/// 两个后端的对端标识体系完全不同：iroh 是公钥指纹（`EndpointId`），
/// rustp2p 是任意字符串（`PeerId`）。这里各存各的，避免互相污染。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerRef {
    /// iroh 的 endpoint id。
    Iroh(IrohEndpointId),
    /// rustp2p 的 peer id（任意字符串）。
    Rustp2p(String),
}

impl PeerRef {
    /// 用于展示与比较的字符串形式。
    pub fn as_str(&self) -> String {
        match self {
            PeerRef::Iroh(id) => id.to_string(),
            PeerRef::Rustp2p(s) => s.clone(),
        }
    }

    /// 该对端标识属于哪个后端。
    pub fn kind(&self) -> TransportKind {
        match self {
            PeerRef::Iroh(_) => TransportKind::Iroh,
            PeerRef::Rustp2p(_) => TransportKind::Rustp2p,
        }
    }
}

impl std::fmt::Display for PeerRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_str())
    }
}

/// 路径状态 —— 两个后端都归一化到这里。
///
/// 这是本项目最重要的运行时指标：它把「到底有没有打洞成功」从猜测变成事实。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathState {
    /// 正在连接中。
    Connecting,
    /// 走中继转发。
    Relay {
        /// 中继地址（relay url 或中继 peer id）。
        relay: String,
        /// 往返时延。
        rtt: Option<Duration>,
    },
    /// 已建立公网直连（打洞成功）。
    Direct {
        /// 远端公网端点。
        remote: String,
        /// 往返时延。
        rtt: Option<Duration>,
    },
    /// 连接失败。
    Failed {
        /// 失败原因。
        reason: String,
    },
}

impl PathState {
    /// 是否为直连（打洞成功）。
    pub fn is_direct(&self) -> bool {
        matches!(self, PathState::Direct { .. })
    }

    /// 是否走中继。
    pub fn is_relay(&self) -> bool {
        matches!(self, PathState::Relay { .. })
    }

    /// 是否已连通（直连或中继都算）。
    pub fn is_connected(&self) -> bool {
        self.is_direct() || self.is_relay()
    }

    /// 当前路径的远端标识。
    pub fn remote(&self) -> Option<&str> {
        match self {
            PathState::Relay { relay, .. } => Some(relay.as_str()),
            PathState::Direct { remote, .. } => Some(remote.as_str()),
            _ => None,
        }
    }

    /// 当前路径的往返时延。
    pub fn rtt(&self) -> Option<Duration> {
        match self {
            PathState::Relay { rtt, .. } | PathState::Direct { rtt, .. } => *rtt,
            _ => None,
        }
    }

    /// 转成 v0.2 的 [`PathInfo`]，供既有的展示函数复用。
    pub fn to_path_info(&self) -> Option<PathInfo> {
        match self {
            PathState::Relay { relay, rtt } => Some(PathInfo {
                kind: PathKind::Relay,
                remote: relay.clone(),
                rtt: *rtt,
            }),
            PathState::Direct { remote, rtt } => Some(PathInfo {
                kind: PathKind::Direct,
                remote: remote.clone(),
                rtt: *rtt,
            }),
            _ => None,
        }
    }

    /// 由 [`PathInfo`] 反推路径状态。
    pub fn from_path_info(info: &PathInfo) -> Self {
        match info.kind {
            PathKind::Direct => PathState::Direct {
                remote: info.remote.clone(),
                rtt: info.rtt,
            },
            PathKind::Relay => PathState::Relay {
                relay: info.remote.clone(),
                rtt: info.rtt,
            },
        }
    }
}

/// 路径状态变化事件 —— 与 `src/pathinfo.rs` 已有的语义对齐。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportEvent {
    /// 一条路径被打开（不一定是当前生效的那条）。
    PathOpened {
        /// 路径的远端标识。
        remote: String,
    },
    /// 当前生效路径被选中 —— 「中继 → 直连」的迁移就发生在这里。
    PathSelected {
        /// 路径类型。
        kind: PathKind,
        /// 路径的远端标识。
        remote: String,
        /// 往返时延。
        rtt: Option<Duration>,
    },
    /// 一条路径被关闭。
    PathClosed {
        /// 路径的远端标识。
        remote: String,
    },
}

/// 把路径状态映射成事件。
///
/// `Connecting` 映射为 [`TransportEvent::PathOpened`]（一条路径正在建立），
/// `Failed` 映射为 [`TransportEvent::PathClosed`]（路径没能建立起来）。
pub fn to_event(state: &PathState) -> TransportEvent {
    match state {
        PathState::Connecting => TransportEvent::PathOpened {
            remote: String::new(),
        },
        PathState::Relay { relay, rtt } => TransportEvent::PathSelected {
            kind: PathKind::Relay,
            remote: relay.clone(),
            rtt: *rtt,
        },
        PathState::Direct { remote, rtt } => TransportEvent::PathSelected {
            kind: PathKind::Direct,
            remote: remote.clone(),
            rtt: *rtt,
        },
        PathState::Failed { reason } => TransportEvent::PathClosed {
            remote: reason.clone(),
        },
    }
}

/// 一条可读写的字节流。
///
/// RDP 隧道只关心「字节能从这边流到那边」，所以这一层就是
/// `AsyncRead + AsyncWrite`，具体是 QUIC 流还是 TCP 连接都无所谓。
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}

/// 一条入站流及其来源。
pub struct AcceptedStream {
    /// 对端标识。
    pub peer: PeerRef,
    /// 流本身。
    pub stream: Box<dyn AsyncStream>,
}

/// 传输层端点 —— 隧道逻辑与具体传输后端之间的唯一接口。
///
/// 生命周期与 iroh 的 [`iroh::Endpoint`] 一致：`bind` 之后即可用，
/// [`TransportEndpoint::close`] 之后所有操作都会失败。
#[async_trait::async_trait]
// async-trait 生成的 `#[must_use]` 没有消息，而返回的 `Result` 本身已是 must_use，
// 会触发 clippy::double_must_use。
#[allow(clippy::double_must_use)]
pub trait TransportEndpoint: Send + Sync {
    /// 后端种类。
    fn kind(&self) -> TransportKind;

    /// 本端标识（展示用）。
    fn local_id(&self) -> String;

    /// 主动打开一条到对端的流。
    ///
    /// 实现应保证「连接刚断」这类瞬时失败能自愈 —— 至少重试一次。
    async fn open_stream(&self, peer: &PeerRef) -> anyhow::Result<Box<dyn AsyncStream>>;

    /// 接受一条入站流。
    ///
    /// 每次调用返回**一条**流；同一个对端可以有多条流。
    async fn accept_stream(&self) -> anyhow::Result<AcceptedStream>;

    /// 当前路径状态。
    fn path_state(&self) -> PathState;

    /// 订阅路径事件。
    fn subscribe(&self) -> broadcast::Receiver<TransportEvent>;

    /// 关闭端点。
    async fn close(&self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_kind_parses_both_backends() {
        assert_eq!(TransportKind::parse("iroh").unwrap(), TransportKind::Iroh);
        assert_eq!(
            TransportKind::parse("rustp2p").unwrap(),
            TransportKind::Rustp2p
        );
        assert_eq!(TransportKind::parse("R2P").unwrap(), TransportKind::Rustp2p);
        assert!(TransportKind::parse("quic").is_err());
    }

    #[test]
    fn peer_ref_reports_its_kind() {
        let p = PeerRef::Rustp2p("peer-c".to_string());
        assert_eq!(p.kind(), TransportKind::Rustp2p);
        assert_eq!(p.as_str(), "peer-c");
        assert_eq!(p.to_string(), "peer-c");
    }

    #[test]
    fn path_state_distinguishes_direct_from_relay() {
        let direct = PathState::Direct {
            remote: "171.37.192.67:34622".into(),
            rtt: Some(Duration::from_millis(37)),
        };
        assert!(direct.is_direct());
        assert!(!direct.is_relay());
        assert!(direct.is_connected());
        assert_eq!(direct.rtt(), Some(Duration::from_millis(37)));
        assert_eq!(direct.remote(), Some("171.37.192.67:34622"));

        let relay = PathState::Relay {
            relay: "https://aps1-1.relay.n0.iroh.link./".into(),
            rtt: None,
        };
        assert!(relay.is_relay());
        assert!(!relay.is_direct());
        assert!(relay.is_connected());
        assert_eq!(relay.rtt(), None);
    }

    #[test]
    fn connecting_and_failed_are_not_connected() {
        assert!(!PathState::Connecting.is_connected());
        assert!(!PathState::Connecting.is_direct());
        assert!(!PathState::Connecting.is_relay());
        assert_eq!(PathState::Connecting.remote(), None);

        let failed = PathState::Failed {
            reason: "连接超时".into(),
        };
        assert!(!failed.is_connected());
        assert_eq!(failed.remote(), None);
    }

    #[test]
    fn path_state_round_trips_through_path_info() {
        let direct = PathState::Direct {
            remote: "1.2.3.4:5".into(),
            rtt: Some(Duration::from_millis(11)),
        };
        let info = direct.to_path_info().unwrap();
        assert_eq!(info.kind, PathKind::Direct);
        assert_eq!(PathState::from_path_info(&info), direct);

        let relay = PathState::Relay {
            relay: "https://relay.example./".into(),
            rtt: None,
        };
        let info = relay.to_path_info().unwrap();
        assert_eq!(info.kind, PathKind::Relay);
        assert_eq!(PathState::from_path_info(&info), relay);
    }

    #[test]
    fn to_event_maps_every_state() {
        assert!(matches!(
            to_event(&PathState::Connecting),
            TransportEvent::PathOpened { .. }
        ));
        assert!(matches!(
            to_event(&PathState::Direct {
                remote: "1.2.3.4:5".into(),
                rtt: None
            }),
            TransportEvent::PathSelected {
                kind: PathKind::Direct,
                ..
            }
        ));
        assert!(matches!(
            to_event(&PathState::Relay {
                relay: "r".into(),
                rtt: None
            }),
            TransportEvent::PathSelected {
                kind: PathKind::Relay,
                ..
            }
        ));
        assert!(matches!(
            to_event(&PathState::Failed { reason: "x".into() }),
            TransportEvent::PathClosed { .. }
        ));
    }

    #[test]
    fn to_event_keeps_remote_and_rtt() {
        let e = to_event(&PathState::Direct {
            remote: "171.37.192.67:34622".into(),
            rtt: Some(Duration::from_millis(37)),
        });
        match e {
            TransportEvent::PathSelected { kind, remote, rtt } => {
                assert_eq!(kind, PathKind::Direct);
                assert_eq!(remote, "171.37.192.67:34622");
                assert_eq!(rtt, Some(Duration::from_millis(37)));
            }
            other => panic!("期望 PathSelected，实际: {other:?}"),
        }
    }
}
