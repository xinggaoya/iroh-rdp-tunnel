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
use iroh::{Endpoint, TransportAddr, endpoint::Connection, endpoint::PathEvent};
use std::sync::{Arc, Mutex};

use crate::netaddr::{is_global_v4, is_global_v6};

/// 直连观察窗口：连接建立后多久还没出现直连路径，就提示当前走中继。
pub const DIRECT_WAIT_WINDOW: Duration = Duration::from_secs(30);

/// 判断一个传输地址是否是**公网**端点（而非私网 / 回环 / 链路本地）。
///
/// 路径事件里会同时冒出本机各张虚拟网卡的私网地址，那些开关纯属噪音；
/// 打洞真正关心的是公网端点。
pub fn is_public_endpoint(addr: &TransportAddr) -> bool {
    match addr {
        TransportAddr::Ip(sa) => match sa {
            std::net::SocketAddr::V4(v4) => is_global_v4(v4.ip()),
            std::net::SocketAddr::V6(v6) => is_global_v6(v6.ip()),
        },
        _ => false,
    }
}

/// 读取端点当前连上的 home relay（没连上则返回 None）。
pub fn home_relay(endpoint: &Endpoint) -> Option<String> {
    use iroh::Watcher as _;
    endpoint
        .home_relay_status()
        .get()
        .into_iter()
        .find(|s| s.is_connected())
        .map(|s| s.url().to_string())
}

/// 判断「路径实际用的中继」与「本端 home relay」是否不一致。
///
/// 两端各自自动选 relay 时经常选到不同���家 —— 流量就得先到本端的中继、
/// 再由它转发到对端的中继（多一跳），延迟直接叠加。
/// 实测见过：服务端 euc1-1（欧洲）、客户端 usw1-1（美西），
/// 路径 RTT 被拉到 1152ms。
pub fn relay_mismatch(path_relay: &str, home_relay: Option<&str>) -> bool {
    match home_relay {
        Some(home) => normalize_relay(home) != normalize_relay(path_relay),
        None => false,
    }
}

/// 归一化 relay URL（去掉末尾的 `.` 与 `/`）。
///
/// `RelayUrl` 的规范形式是 `https://host./`（带 DNS 根尾点），
/// 而路径事件里的字符串可能是 `https://host./` 也可能少一个尾点 —— 不归一化就会误判。
pub fn normalize_relay(url: &str) -> String {
    url.trim_end_matches(['.', '/']).to_string()
}

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

/// 若路径用的中继与本端 home relay 不一致，打印告警。
///
/// 两端各自自动选 relay 时经常选到不同家 —— 流量要先到本端的中继，
/// 再由它转发到对端的中继（多一跳），延迟直接叠加。
fn warn_relay_mismatch(endpoint: &Endpoint, tag: &str, info: &PathInfo) {
    if info.kind != PathKind::Relay {
        return;
    }
    let home = home_relay(endpoint);
    if relay_mismatch(&info.remote, home.as_deref()) {
        println!(
            " [路径·{tag}] ⚠ 路径经由 {} 中转，但本端连的是 {} —— 多了一跳中继转发",
            info.remote,
            home.as_deref().unwrap_or("?")
        );
        println!(
            " [路径·{tag}]   ↳ 两端用**同一个** relay 可省掉这一跳：--relay https://aps1-1.relay.n0.iroh.link./"
        );
    }
}

/// 启动一个路径报告器，把路径变化打印到标准输出。
///
/// `tag` 用来区分是 server 侧还是 client 侧打印的。
///
/// 输出形如：
/// ```text
///  [路径·client] 中继  https://aps1-1.relay.n0.iroh.link./  RTT 41ms
///  [路径·client] 🔓 直连路径已打开  171.37.192.67:34622
///  [路径·client] ✅ 已切换到直连  171.37.192.67:34622  RTT 37ms
/// ```
///
/// **不只打印被选中的路径** —— 直连路径「被打开又关闭」是打洞失败最直接的证据，
/// 只看选中路径的话会得到一片空白，无法区分「没尝试打洞」和「打了但没通」。
pub fn spawn_path_reporter(
    conn: Connection,
    tag: &str,
    endpoint: Endpoint,
) -> tokio::task::JoinHandle<()> {
    let tag = tag.to_string();
    let tag_events = tag.clone();
    let last = Arc::new(std::sync::Mutex::new(None::<(PathKind, String)>));
    let last2 = Arc::clone(&last);
    // 先把**当前**路径打一遍，避免错过订阅前的迁移。
    let mut events = conn.path_events();
    let saw_direct = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let saw_direct2 = Arc::clone(&saw_direct);
    let handle = tokio::spawn(async move {
        if let Some(info) = describe_path(&conn) {
            report(&last2, &tag_events, &info);
            warn_relay_mismatch(&endpoint, &tag_events, &info);
        }
        while let Some(event) = events.next().await {
            match event {
                PathEvent::Opened { remote_addr, .. } => {
                    // 只关心**公网**直连端点：私网地址的开关是虚拟网卡造成的噪音。
                    if is_public_endpoint(&remote_addr) {
                        saw_direct2.store(true, std::sync::atomic::Ordering::Relaxed);
                        println!(" [路径·{tag_events}] 🔓 公网直连路径已打开  {remote_addr}");
                    }
                }
                PathEvent::Selected { .. } => {
                    if let Some(info) = describe_path(&conn) {
                        if info.kind == PathKind::Direct {
                            saw_direct2.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                        report(&last2, &tag_events, &info);
                        warn_relay_mismatch(&endpoint, &tag_events, &info);
                    }
                }
                PathEvent::Closed { remote_addr, .. } => {
                    if is_public_endpoint(&remote_addr) {
                        println!(" [路径·{tag_events}] ❌ 公网直连路径已关闭  {remote_addr}");
                    } else if !remote_addr.is_ip() {
                        println!(" [路径·{tag_events}] ⚠ 中继路径已关闭  {remote_addr}");
                    }
                }
                // PathEvent 是 #[non_exhaustive]，未来新增变体时静默忽略。
                _ => {}
            }
        }
    });

    // 观察窗口：连接建立后一段时间还没直连，就明确告知「当前走中继」。
    // 否则用户只能看到「中继」两个字，不知道是还没打洞成功还是压根打不了。
    let tag2 = tag.clone();
    tokio::spawn(async move {
        tokio::time::sleep(DIRECT_WAIT_WINDOW).await;
        if !saw_direct.load(std::sync::atomic::Ordering::Relaxed) {
            println!(
                " [路径·{tag2}] ⚠ {} 秒内未建立**公网**直连路径，当前走中继（RDP 可用，延迟偏高）",
                DIRECT_WAIT_WINDOW.as_secs()
            );
            println!(
                " [路径·{tag2}]   ↳ 排查 1：两端是否用了**同一个** relay？（对比两端启动时的中继地址）"
            );
            println!(
                " [路径·{tag2}]   ↳ 排查 2：对端 NAT 映射随目标变化（非 EIM）\
                 → 对端需做端口映射或换网络"
            );
        }
    });

    handle
}

/// 打印一次路径变化（去重：同一路径 + 同一地址不重复打印）。
fn report(last: &Mutex<Option<(PathKind, String)>>, tag: &str, info: &PathInfo) {
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

    #[test]
    fn public_endpoint_detection_filters_private_addresses() {
        let public = TransportAddr::Ip("171.37.192.67:34622".parse().unwrap());
        let private = TransportAddr::Ip("192.168.0.138:34622".parse().unwrap());
        let link_local = TransportAddr::Ip("[fe80::1]:34622".parse().unwrap());
        let relay = TransportAddr::Relay("https://aps1-1.relay.n0.iroh.link./".parse().unwrap());
        assert!(is_public_endpoint(&public));
        assert!(!is_public_endpoint(&private));
        assert!(!is_public_endpoint(&link_local));
        assert!(!is_public_endpoint(&relay));
    }

    #[test]
    fn relay_mismatch_detects_different_relays() {
        // 实测踩过的坑：服务端 euc1-1（欧洲）、客户端 usw1-1（美西），
        // 路径 RTT 被拉到 1152ms。
        assert!(relay_mismatch(
            "https://euc1-1.relay.n0.iroh.link./",
            Some("https://usw1-1.relay.n0.iroh.link./")
        ));
    }

    #[test]
    fn relay_mismatch_ignores_trailing_slash() {
        assert!(!relay_mismatch(
            "https://aps1-1.relay.n0.iroh.link./",
            Some("https://aps1-1.relay.n0.iroh.link")
        ));
        assert!(!relay_mismatch(
            "https://aps1-1.relay.n0.iroh.link./",
            Some("https://aps1-1.relay.n0.iroh.link./")
        ));
    }

    #[test]
    fn relay_mismatch_is_silent_without_home_relay() {
        assert!(!relay_mismatch(
            "https://euc1-1.relay.n0.iroh.link./",
            None
        ));
    }
}
