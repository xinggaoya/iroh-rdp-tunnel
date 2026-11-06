//! 控制端的常驻连接管理器。
//!
//! 为什么不用「每个 TCP 连接新建一条 QUIC 连接」：
//! 那样每次打开 mstsc 都要重新握手、重新打洞，首帧延迟高且平白消耗中继流量。
//! 这里维持**一条**长连接，断线后按指数退避自动重连。

use std::time::{Duration, Instant};

use anyhow::Result;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use tokio::sync::watch;

use crate::{ALPN, pathinfo::spawn_path_reporter};

/// 首次重连前的等待时长。
pub const BASE_RECONNECT_DELAY: Duration = Duration::from_millis(200);

/// 重连等待时长的上限。
pub const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// 连接稳定存活多久之后，重连退避才重置回起点。
pub const STABLE_CONN_DURATION: Duration = Duration::from_secs(30);

/// 第 `attempt` 次失败后的等待时长（200ms → 400ms → 800ms …，上限 5s）。
pub fn reconnect_delay(attempt: u32) -> Duration {
    let exp = attempt.min(16);
    let ms = BASE_RECONNECT_DELAY
        .as_millis()
        .saturating_mul(1u128 << exp)
        .min(MAX_RECONNECT_DELAY.as_millis());
    Duration::from_millis(ms as u64)
}

/// 维持一条到远端的 QUIC 连接，断线自动重连。
#[derive(Clone)]
pub struct ConnManager {
    remote: EndpointId,
    #[allow(dead_code)]
    endpoint: Endpoint,
    /// 要拨号的远端地址。`EndpointAddr::from(id)` 的地址集是空的，
    /// iroh 会通过地址发现（DNS pkarr）补全。
    #[allow(dead_code)]
    target: EndpointAddr,
    conn_rx: watch::Receiver<Option<iroh::endpoint::Connection>>,
}

impl ConnManager {
    /// 启动后台连接任务，立即开始第一次连接尝试。
    ///
    /// 远端地址通过 endpoint id 解析（需要地址发现可用）。
    pub fn start(endpoint: Endpoint, remote: EndpointId) -> Self {
        Self::start_with_addr(endpoint, remote, EndpointAddr::from(remote))
    }

    /// 启动后台连接任务，并**直接指定**远端地址。
    ///
    /// 用于自建 relay（已知 relay URL）、地址发现关闭、或集成测试的场景。
    pub fn start_with_addr(endpoint: Endpoint, remote: EndpointId, target: EndpointAddr) -> Self {
        let (tx, rx) = watch::channel(None);
        tokio::spawn(connection_loop(
            endpoint.clone(),
            remote,
            target.clone(),
            tx,
        ));
        Self {
            remote,
            endpoint,
            target,
            conn_rx: rx,
        }
    }

    /// 远端 endpoint id。
    pub fn remote(&self) -> EndpointId {
        self.remote
    }

    /// 当前连接（若有），**不等待**。
    ///
    /// 已经关闭的连接会被跳过 —— 拿到一条死连接比拿不到更糟。
    /// 供路径状态轮询使用（不能为了看一眼路径状态就阻塞等待）。
    pub fn current(&self) -> Option<iroh::endpoint::Connection> {
        self.conn_rx
            .borrow()
            .clone()
            .filter(|c| c.close_reason().is_none())
    }

    /// 取当前可用连接；尚无连接则等待，最多等 `timeout`。
    ///
    /// 会跳过**已经关闭**的连接：连接刚断时，后台任务还没来得及把 watch 里的
    /// 连接清空，这时拿到的是一条死连接 —— 直接用会在 `open_bi` 上失败。
    pub async fn connection(&self, timeout: Duration) -> Result<iroh::endpoint::Connection> {
        let mut rx = self.conn_rx.clone();
        tokio::time::timeout(timeout, async move {
            loop {
                if let Some(conn) = rx.borrow().clone() {
                    if conn.close_reason().is_none() {
                        return Ok(conn);
                    }
                    // 已经断了 —— 等后台任务换成新连接。
                    tracing::debug!("当前连接已关闭，等待重连");
                }
                if rx.changed().await.is_err() {
                    anyhow::bail!("连接管理器已停止");
                }
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("连接远端超时（{} 秒）", timeout.as_secs()))?
    }
}

/// 后台连接循环：连接 → 等待断开 → 退避重连。
async fn connection_loop(
    endpoint: Endpoint,
    remote: EndpointId,
    target: EndpointAddr,
    tx: watch::Sender<Option<iroh::endpoint::Connection>>,
) {
    let mut attempt: u32 = 0;
    loop {
        match endpoint.connect(target.clone(), ALPN).await {
            Ok(conn) => {
                let connected_at = Instant::now();
                tracing::info!("已与远端 {remote} 建立连接");
                spawn_path_reporter(conn.clone(), "client", endpoint.clone());
                let _ = tx.send(Some(conn.clone()));
                // 等连接关闭（对端断开或传输出错）后再重连。
                let _ = conn.closed().await;
                let _ = tx.send(None);
                tracing::warn!("与远端 {remote} 的连接已断开，准备重连");
                // 只有**稳定存活**过一段时间才把退避重置回起点。
                // 否则「连上 → 立刻被断开 → 200ms 后再连上」会变成高速循环。
                if connected_at.elapsed() >= STABLE_CONN_DURATION {
                    attempt = 0;
                }
            }
            Err(e) => {
                tracing::warn!("连接远端 {remote} 失败: {e:#}");
            }
        }
        let delay = reconnect_delay(attempt);
        attempt = attempt.saturating_add(1);
        tokio::time::sleep(delay).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_each_attempt() {
        assert_eq!(reconnect_delay(0), Duration::from_millis(200));
        assert_eq!(reconnect_delay(1), Duration::from_millis(400));
        assert_eq!(reconnect_delay(2), Duration::from_millis(800));
        assert_eq!(reconnect_delay(3), Duration::from_millis(1600));
        assert_eq!(reconnect_delay(4), Duration::from_millis(3200));
    }

    #[test]
    fn backoff_caps_at_five_seconds() {
        assert_eq!(reconnect_delay(5), Duration::from_millis(5000));
        assert_eq!(reconnect_delay(20), Duration::from_millis(5000));
        assert_eq!(reconnect_delay(u32::MAX), Duration::from_millis(5000));
    }

    #[test]
    fn stable_connection_duration_is_sane() {
        assert!(STABLE_CONN_DURATION > BASE_RECONNECT_DELAY);
        assert!(STABLE_CONN_DURATION <= Duration::from_secs(300));
    }

    #[test]
    fn backoff_never_overflows() {
        // attempt 极大时不能 panic 或回绕
        for a in [0u32, 15, 16, 17, 63, 64, 1000, u32::MAX] {
            let d = reconnect_delay(a);
            assert!(d >= BASE_RECONNECT_DELAY);
            assert!(d <= MAX_RECONNECT_DELAY);
        }
    }
}
