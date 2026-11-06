//! 连接路径的可观测性：这条连接当前走的是**直连**还是**中继**。
//!
//! 这是本项目最重要的运行时指标 —— 它把「到底有没有打洞成功」从猜测变成事实。
//!
//! 对照 iroh 1.0.2 源码：
//! - `Connection::paths()` → [`PathList`]，其中一条路径的 `is_selected()` 为真即为当前路径
//! - `Path::is_ip()` / `Path::is_relay()` → 判定直连还是中继
//! - `Path::remote_addr()` → 远端传输地址
//! - `Path::rtt()` → 往返时延估计
//! - `Connection::path_events()` → 路径生命周期事件（打开 / 关闭 / 被选中）

use std::time::Duration;

use futures::StreamExt;
use iroh::{TransportAddr, endpoint::Connection, endpoint::PathEvent};
use std::sync::{Arc, Mutex};

/// 路径类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// 直连 IP 路径（打洞成功）。
    Direct,
    /// 经中继转发。
    Relay,
}

impl PathKind {
    /// 中文标签。
    pub fn label(self) -> &'static str {
        match self {
            PathKind::Direct => "直连",
            PathKind::Relay => "中继",
        }
    }
}

/// 当前路径的快照。
#[derive(Debug, Clone)]
pub struct PathInfo {
    /// 路径类型。
    pub kind: PathKind,
    /// 远端地址（IP:port 或 relay url）。
    pub remote: String,
    /// 往返时延。
    pub rtt: Option<Duration>,
}

/// 由传输地址判定路径类型。
///
/// 自定义传输（`Custom`）既不是直连 IP 也不是 relay，归为中继 ——
/// 保守起见不把它当成「已经打洞成功」。
pub fn classify(addr: &TransportAddr) -> PathKind {
    classify_by_is_ip(addr.is_ip())
}

/// 判定逻辑本体（与 `TransportAddr` 解耦，便于单测）。
///
/// `TransportAddr::Custom` 的具体类型没有从 `iroh` 导出，外部无法构造，
/// 所以把判定拆成这个纯函数来覆盖。
pub fn classify_by_is_ip(is_ip: bool) -> PathKind {
    if is_ip {
        PathKind::Direct
    } else {
        PathKind::Relay
    }
}

/// 把一条路径的信息汇总成 [`PathInfo`]；未被选中则返回 `None`。
pub fn info_from(
    is_selected: bool,
    addr: &TransportAddr,
    rtt: Option<Duration>,
) -> Option<PathInfo> {
    if !is_selected {
        return None;
    }
    Some(PathInfo {
        kind: classify(addr),
        remote: match addr {
            TransportAddr::Ip(sa) => sa.to_string(),
            TransportAddr::Relay(url) => url.to_string(),
            TransportAddr::Custom(c) => format!("{c:?}"),
            // TransportAddr 是 #[non_exhaustive]，未来新增变体时兜底。
            _ => format!("{addr:?}"),
        },
        rtt,
    })
}

/// 读取连接当前**被选中**的路径。
pub fn describe_path(conn: &Connection) -> Option<PathInfo> {
    let paths = conn.paths();
    for path in paths.iter() {
        if let Some(info) = info_from(path.is_selected(), path.remote_addr(), Some(path.rtt())) {
            return Some(info);
        }
    }
    None
}

/// 订阅路径变更；路径被选中或切换时回调。
///
/// 回调会在「中继 → 直连」迁移发生时触发 —— 那一刻就是打洞成功的时刻。
pub fn spawn_path_monitor(
    conn: Connection,
    on_change: impl Fn(PathInfo) + Send + Sync + 'static,
) -> tokio::task::JoinHandle<()> {
    // **同步订阅**（在 spawn 之前）：事件流是广播通道，
    // 晚订阅会丢掉订阅之前发生的事件（例如中继→直连的迁移）。
    let mut events = conn.path_events();
    tokio::spawn(async move {
        while let Some(event) = events.next().await {
            match event {
                PathEvent::Opened { .. } | PathEvent::Selected { .. } => {
                    if let Some(info) = describe_path(&conn) {
                        on_change(info);
                    }
                }
                PathEvent::Closed { .. } | PathEvent::Lagged { .. } => {}
                // PathEvent 是 #[non_exhaustive]，未来新增变体时静默忽略。
                _ => {}
            }
        }
    })
}

/// 人类可读的路径描述。
pub fn describe(info: &PathInfo) -> String {
    match info.rtt {
        Some(rtt) => format!("{} {} (RTT {}ms)", info.kind.label(), info.remote, rtt.as_millis()),
        None => format!("{} {}", info.kind.label(), info.remote),
    }
}

/// 路径变化时的提示文案（抽出来便于单测）。
pub fn transition_label(prev: Option<PathKind>, now: PathKind) -> &'static str {
    match (prev, now) {
        (None, PathKind::Direct) => "直连",
        (None, PathKind::Relay) => "中继",
        (Some(PathKind::Relay), PathKind::Direct) => "✅ 已切换到直连",
        (Some(PathKind::Direct), PathKind::Relay) => "⚠ 已回落到中继",
        _ => now.label(),
    }
}

/// 启动一个路径报告器，把路径变化打印到标准输出。
///
/// `tag` 用来区分是 server 侧还是 client 侧打印的。
///
/// 输出形如：
/// ```text
///  [路径·client] 中继  https://aps1-1.relay.n0.iroh.link./  RTT 41ms
///  [路径·client] ✅ 已切换到直连  171.37.192.67:34622  RTT 37ms
/// ```
pub fn spawn_path_reporter(conn: Connection, tag: &str) -> tokio::task::JoinHandle<()> {
    let tag = tag.to_string();
    let last = Arc::new(std::sync::Mutex::new(None::<(PathKind, String)>));
    let last2 = Arc::clone(&last);
    // 先把**当前**路径打一遍，避免错过订阅前的迁移。
    let mut events = conn.path_events();
    tokio::spawn(async move {
        if let Some(info) = describe_path(&conn) {
            report(&last2, &tag, info);
        }
        while let Some(event) = events.next().await {
            match event {
                PathEvent::Opened { .. } | PathEvent::Selected { .. } => {
                    if let Some(info) = describe_path(&conn) {
                        report(&last2, &tag, info);
                    }
                }
                PathEvent::Closed { .. } | PathEvent::Lagged { .. } => {}
                // PathEvent 是 #[non_exhaustive]，未来新增变体时静默忽略。
                _ => {}
            }
        }
    })
}

/// 打印一次路径变化（去重：同一路径 + 同一地址不重复打印）。
fn report(last: &Mutex<Option<(PathKind, String)>>, tag: &str, info: PathInfo) {
    let mut prev = last.lock().unwrap();
    let key = (info.kind, info.remote.clone());
    if *prev == Some(key.clone()) {
        // 同一路径、同一地址：RTT 的日常波动不刷屏。
        return;
    }
    let prev_kind = prev.as_ref().map(|(k, _)| *k);
    let prefix = transition_label(prev_kind, info.kind).to_string();
    *prev = Some(key);
    let rtt = match info.rtt {
        Some(rtt) => format!("  RTT {}ms", rtt.as_millis()),
        None => String::new(),
    };
    println!(" [路径·{tag}] {prefix}  {}{rtt}", info.remote);
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::RelayUrl;

    #[test]
    fn ip_address_is_direct() {
        let addr = TransportAddr::Ip("171.37.192.67:34622".parse().unwrap());
        assert_eq!(classify(&addr), PathKind::Direct);
    }

    #[test]
    fn relay_address_is_relay() {
        let url: RelayUrl = "https://aps1-1.relay.n0.iroh.link.".parse().unwrap();
        let addr = TransportAddr::Relay(url);
        assert_eq!(classify(&addr), PathKind::Relay);
    }

    #[test]
    fn non_ip_addresses_are_treated_as_relay() {
        // 自定义传输（Custom）既不是直连 IP 也不是 relay ——
        // 保守起见不把它当成「已经打洞成功」。
        assert_eq!(classify_by_is_ip(false), PathKind::Relay);
        assert_eq!(classify_by_is_ip(true), PathKind::Direct);
    }

    #[test]
    fn labels_are_chinese() {
        assert_eq!(PathKind::Direct.label(), "直连");
        assert_eq!(PathKind::Relay.label(), "中继");
    }

    #[test]
    fn info_from_ignores_unselected_paths() {
        let addr = TransportAddr::Ip("1.2.3.4:5".parse().unwrap());
        assert!(info_from(false, &addr, None).is_none());
    }

    #[test]
    fn info_from_keeps_selected_paths() {
        let addr = TransportAddr::Ip("171.37.192.67:34622".parse().unwrap());
        let info = info_from(true, &addr, Some(Duration::from_millis(37))).unwrap();
        assert_eq!(info.kind, PathKind::Direct);
        assert_eq!(info.remote, "171.37.192.67:34622");
        assert_eq!(info.rtt, Some(Duration::from_millis(37)));
    }

    #[test]
    fn info_from_renders_relay_url() {
        let url: RelayUrl = "https://aps1-1.relay.n0.iroh.link.".parse().unwrap();
        let info = info_from(true, &TransportAddr::Relay(url), None).unwrap();
        assert_eq!(info.kind, PathKind::Relay);
        assert!(info.remote.contains("relay.n0.iroh.link"), "实际: {}", info.remote);
    }

    #[test]
    fn describe_contains_kind_remote_and_rtt() {
        let addr = TransportAddr::Ip("171.37.192.67:34622".parse().unwrap());
        let info = info_from(true, &addr, Some(Duration::from_millis(37))).unwrap();
        let s = describe(&info);
        assert!(s.contains("直连"), "实际: {s}");
        assert!(s.contains("171.37.192.67:34622"), "实际: {s}");
        assert!(s.contains("37ms"), "实际: {s}");
    }

    #[test]
    fn describe_without_rtt_omits_rtt() {
        let addr = TransportAddr::Ip("1.2.3.4:5".parse().unwrap());
        let info = info_from(true, &addr, None).unwrap();
        let s = describe(&info);
        assert!(!s.contains("RTT"), "没有 RTT 时不应出现 RTT 字样，实际: {s}");
    }

    #[test]
    fn transition_labels_cover_all_cases() {
        assert_eq!(transition_label(None, PathKind::Relay), "中继");
        assert_eq!(transition_label(None, PathKind::Direct), "直连");
        assert_eq!(
            transition_label(Some(PathKind::Relay), PathKind::Direct),
            "✅ 已切换到直连"
        );
        assert_eq!(
            transition_label(Some(PathKind::Direct), PathKind::Relay),
            "⚠ 已回落到中继"
        );
        assert_eq!(
            transition_label(Some(PathKind::Direct), PathKind::Direct),
            "直连"
        );
    }
}
