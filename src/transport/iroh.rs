//! iroh 后端的传输层适配器。
//!
//! 把 v0.2 里散落在 [`crate::endpoint`] / [`crate::connmgr`] / [`crate::pathinfo`]
//! 的逻辑收拢到一个 [`TransportEndpoint`] 实现里，**行为保持不变**：
//!
//! - server 侧：用 [`Router`] 接受入站连接 → 每条连接上逐条接受双向流；
//! - client 侧：维持**一条**常驻连接，断线后指数退避重连（[`crate::connmgr`]）；
//! - 路径可观测：沿用 v0.2 的 [`crate::pathinfo`]，输出格式与时机完全一致；
//!   同时额外把事件推到广播通道，供上层消费。
//!
//! # 为什么用 Router 而不是 `Endpoint::accept()`
//!
//! iroh 1.0.2 的 `Endpoint::accept()` 返回的 `Incoming` 只能拿到 `Accepting`，
//! 而 `Accepting` **没有**公开的「完成握手并拿到 `Connection`」的方法
//! （`register_with_socket` 是私有的）。公开的完成握手路径只有
//! [`ProtocolHandler::accept`]，也就是 Router —— v0.2 用的正是它。

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use iroh::{
    Endpoint, EndpointAddr, EndpointId,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler, Router},
};
use tokio::sync::{broadcast, mpsc};

use crate::{
    ALPN,
    connmgr::ConnManager,
    pathinfo::{describe_path, spawn_path_monitor, spawn_path_reporter},
    transport::{
        AcceptedStream, AsyncStream, PathState, PeerRef, TransportEndpoint, TransportEvent,
        TransportKind,
    },
    tunnel::QuicStream,
};

/// 事件广播通道的容量。
///
/// 订阅者只关心「路径切换」这类低频事件，32 条足够；
/// 满了就丢最旧的（broadcast 的 lagging 语义），绝不能因此阻塞传输。
const EVENT_CHANNEL_CAPACITY: usize = 32;

/// 打开流时等待连接就绪的超时。
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// iroh 传输端点。
pub struct IrohTransport {
    /// 底层 iroh 端点。
    endpoint: Endpoint,
    /// server 侧的 Router 句柄；client 侧为 `None`。
    router: Option<Router>,
    /// 路径事件的广播通道。
    events: broadcast::Sender<TransportEvent>,
    /// 当前路径状态。
    state: Arc<Mutex<PathState>>,
    /// server 侧的入站流队列。
    incoming: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Result<AcceptedStream>>>>,
    /// client 侧的常驻连接管理器。
    conn_mgr: Option<ConnManager>,
}

impl IrohTransport {
    /// 组装 **server 侧**的传输端点。
    ///
    /// `allow_list` 非空时，只有名单里的 endpoint id 能接入 ——
    /// 判定方式与 v0.2 完全一致（握手完成后立刻检查，不在名单里就拒绝）。
    pub fn new_server(endpoint: Endpoint, allow_list: Vec<EndpointId>) -> Arc<Self> {
        let (events, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let (tx, rx) = mpsc::unbounded_channel();
        let state = Arc::new(Mutex::new(PathState::Connecting));

        let collector = StreamCollector {
            tx,
            allow_list,
            endpoint: endpoint.clone(),
            events: events.clone(),
            state: state.clone(),
        };

        let router = Router::builder(endpoint.clone())
            .accept(ALPN, collector)
            .spawn();

        Arc::new(Self {
            endpoint,
            router: Some(router),
            events,
            state,
            incoming: Arc::new(tokio::sync::Mutex::new(rx)),
            conn_mgr: None,
        })
    }

    /// 组装 **client 侧**的传输端点。
    ///
    /// 立即在后台开始建连（打洞也随之开始），不等到用户第一次打开 mstsc。
    pub fn new_client(endpoint: Endpoint, remote: EndpointId, target: Option<EndpointAddr>) -> Arc<Self> {
        let (events, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let state = Arc::new(Mutex::new(PathState::Connecting));

        let conn_mgr = match target {
            Some(addr) => ConnManager::start_with_addr(endpoint.clone(), remote, addr),
            None => ConnManager::start(endpoint.clone(), remote),
        };

        let transport = Arc::new(Self {
            endpoint,
            router: None,
            events,
            state,
            incoming: Arc::new(tokio::sync::Mutex::new(mpsc::unbounded_channel().1)),
            conn_mgr: Some(conn_mgr),
        });

        transport.spawn_path_publisher();
        transport
    }

    /// client 侧：轮询当前路径状态并推到广播通道。
    ///
    /// iroh 的路径事件是**按连接**的，而 client 的连接会因断线重连而更换，
    /// 所以这里改为轮询当前连接 —— 换连接时状态自动跟着换。
    fn spawn_path_publisher(self: &Arc<Self>) {
        let conn_mgr = self.conn_mgr.clone().expect("client 才有 conn_mgr");
        let events = self.events.clone();
        let state = self.state.clone();

        tokio::spawn(async move {
            let mut last: Option<PathState> = None;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let Some(conn) = conn_mgr.current() else {
                    continue;
                };
                let current = match describe_path(&conn) {
                    Some(info) => PathState::from_path_info(&info),
                    None => PathState::Connecting,
                };
                let changed = last.as_ref() != Some(&current);
                *state.lock().unwrap() = current.clone();
                if changed {
                    last = Some(current.clone());
                    let _ = events.send(crate::transport::to_event(&current));
                }
            }
        });
    }
}

/// 把 iroh 的入站连接转成字节流的协议处理器。
///
/// 逻辑与 v0.2 的 `BridgeHandler` 一一对应，区别只在于**它不负责桥接**，
/// 而是把流送进传输层的队列，由上层决定怎么用。
#[derive(Debug)]
struct StreamCollector {
    /// 入站流队列。
    tx: mpsc::UnboundedSender<Result<AcceptedStream>>,
    /// 允许接入的 endpoint id 白名单；空表示不限制。
    allow_list: Vec<EndpointId>,
    /// 本机端点 —— 用于读取 home relay（检测两端中继是否一致）。
    endpoint: Endpoint,
    /// 路径事件广播通道。
    events: broadcast::Sender<TransportEvent>,
    /// 当前路径状态。
    state: Arc<Mutex<PathState>>,
}

impl ProtocolHandler for StreamCollector {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let remote = conn.remote_id();

        if !self.allow_list.is_empty() && !self.allow_list.contains(&remote) {
            let msg = format!("endpoint {remote} 不在白名单内，拒绝接入");
            tracing::warn!("{msg}");
            return Err(AcceptError::from(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                msg,
            )));
        }

        tracing::info!("收到来自 {remote} 的连接");

        // v0.2 的路径报告器：输出格式与时机完全沿用。
        spawn_path_reporter(conn.clone(), "server", self.endpoint.clone());

        // 额外把路径状态推到广播通道。
        let events = self.events.clone();
        let state = self.state.clone();
        spawn_path_monitor(conn.clone(), move |info| {
            let next = PathState::from_path_info(&info);
            *state.lock().unwrap() = next.clone();
            let _ = events.send(crate::transport::to_event(&next));
        });

        loop {
            let (send, recv) = match conn.accept_bi().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::info!("accept 循环结束（{remote}）: {e}");
                    return Ok(());
                }
            };

            let stream: Box<dyn AsyncStream> = Box::new(QuicStream::new(send, recv));
            if self
                .tx
                .send(Ok(AcceptedStream {
                    peer: PeerRef::Iroh(remote),
                    stream,
                }))
                .is_err()
            {
                // 队列已关闭（端点正在关闭）。
                return Ok(());
            }
        }
    }
}

#[async_trait::async_trait]
impl TransportEndpoint for IrohTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Iroh
    }

    fn local_id(&self) -> String {
        self.endpoint.secret_key().public().to_string()
    }

    async fn open_stream(&self, peer: &PeerRef) -> Result<Box<dyn AsyncStream>> {
        let PeerRef::Iroh(_) = peer else {
            anyhow::bail!("iroh 后端只能连接 iroh 类型的对端标识");
        };
        let mgr = self
            .conn_mgr
            .as_ref()
            .context("iroh 后端未配置连接管理器（server 侧不接受主动连接）")?;

        let conn = mgr.connection(CONNECT_TIMEOUT).await?;
        // 连接可能刚好在这一瞬间断开，open_bi 会失败 —— 换一条新连接重试一次。
        let (send, recv) = match conn.open_bi().await {
            Ok(s) => s,
            Err(first) => {
                tracing::warn!("打开 QUIC 双向流失败（连接可能刚断开）: {first}，重试一次");
                let conn = mgr.connection(CONNECT_TIMEOUT).await?;
                conn.open_bi()
                    .await
                    .context("重试后仍无法打开 QUIC 双向流")?
            }
        };
        Ok(Box::new(QuicStream::new(send, recv)))
    }

    async fn accept_stream(&self) -> Result<AcceptedStream> {
        let mut rx = self.incoming.lock().await;
        match rx.recv().await {
            Some(Ok(s)) => Ok(s),
            Some(Err(e)) => Err(e),
            None => anyhow::bail!("iroh 端点已关闭"),
        }
    }

    fn path_state(&self) -> PathState {
        self.state.lock().unwrap().clone()
    }

    fn subscribe(&self) -> broadcast::Receiver<TransportEvent> {
        self.events.subscribe()
    }

    async fn close(&self) {
        if let Some(router) = &self.router {
            // Router::shutdown 会关掉 endpoint。
            let _ = router.shutdown().await;
        }
        let _ = self.endpoint.close().await;
    }
}
