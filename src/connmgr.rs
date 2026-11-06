//! 控制端的常驻连接管理器。
//!
//! 为什么不用「每个 TCP 连接新建一条 QUIC 连接」：
//! 那样每次打开 mstsc 都要重新握手、重新打洞，首帧延迟高且平白消耗中继流量。
//! 这里维持**一条**长连接，断线后按指数退避自动重连。

use std::time::Duration;

use anyhow::Result;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use tokio::sync::watch;

use crate::{ALPN, pathinfo::spawn_path_reporter};

/// 首次重连前的等待时长。
pub const BASE_RECONNECT_DELAY: Duration = Duration::from_millis(200);

/// 重连等待时长的上限。
pub const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(5);

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
    conn_rx: watch::Receiver<Option<iroh::endpoint::Connection>>,
}

impl ConnManager {
    /// 启动后台连接任务，立即开始第一次连接尝试。
    pub fn start(endpoint: Endpoint, remote: EndpointId) -> Self {
        let (tx, rx) = watch::channel(None);
        tokio::spawn(connection_loop(endpoint.clone(), remote, tx));
        Self {
            remote,
            endpoint,
            conn_rx: rx,
        }
    }

    /// 远端 endpoint id。
    pub fn remote(&self) -> EndpointId {
        self.remote
    }

    /// 取当前可用连接；尚无连接则等待，最多等 `timeout`。
    pub async fn connection(&self, timeout: Duration) -> Result<iroh::endpoint::Connection> {
        let mut rx = self.conn_rx.clone();
        tokio::time::timeout(timeout, async move {
            loop {
                if let Some(conn) = rx.borrow().clone() {
                    return Ok(conn);
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
    tx: watch::Sender<Option<iroh::endpoint::Connection>>,
) {
    let mut attempt: u32 = 0;
    loop {
        match endpoint.connect(EndpointAddr::from(remote), ALPN).await {
            Ok(conn) => {
                attempt = 0;
                tracing::info!("已与远端 {remote} 建立连接");
                spawn_path_reporter(conn.clone(), "client");
                let _ = tx.send(Some(conn.clone()));
                // 等连接关闭（对端断开或传输出错）后再重连。
                let _ = conn.closed().await;
                let _ = tx.send(None);
                tracing::warn!("与远端 {remote} 的连接已断开，准备重连");
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
    fn backoff_never_overflows() {
        // attempt 极大时不能 panic 或回绕
        for a in [0u32, 15, 16, 17, 63, 64, 1000, u32::MAX] {
            let d = reconnect_delay(a);
            assert!(d >= BASE_RECONNECT_DELAY);
            assert!(d <= MAX_RECONNECT_DELAY);
        }
    }
}
