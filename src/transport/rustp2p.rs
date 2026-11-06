//! rustp2p-quic 后端的传输层适配器。
//!
//! # 为什么是第二个后端
//!
//! iroh 的打洞候选**只**来自 QAD（中继观测到的端点）。在**对称 NAT**
//! （映射随目标变化）下，中继看到的端口与对端真实可达端口对不上号，
//! 打洞**永远**打不通 —— 这是架构性限制，改配置没用。
//!
//! rustp2p-quic 用「端口预测 + 全局随机扫描」正面解决对称 NAT，
//! 而且它的中继是 mesh 模型的：只转发密文、不终结 TLS，
//! 所以**不需要**专门的中继服务端，一个 node 同时当 bootstrap 与中继即可。
//!
//! # 字节流适配
//!
//! rustp2p-quic 的 `ReliableSendStream` / `ReliableRecvStream` 只暴露了
//! async 便捷方法（`write_all` / `read` / `finish`），**没有** poll 级 API，
//! 底层的 quinn 流字段也是私有的。而 Tokio 的 `AsyncRead` / `AsyncWrite`
//! 是 poll 级的 —— 所以这里用一个「后台任务 + channel」的适配层把它们桥起来。
//!
//! 语义要点：
//!
//! - **写**：数据交给后台任务，由它按序调用 `write_all`。
//!   背压靠有界 channel 实现：流控窗口满时后台任务卡住 → channel 满 →
//!   `poll_write` 返回 `Pending`。
//! - **读**：后台任务循环 `read`，把每个 chunk 送进 channel；
//!   `poll_read` 先从本地缓冲取，取不到再等 channel。
//! - **半关闭**：`poll_shutdown` 发 `Finish` 命令，让后台任务 `finish()`
//!   掉写半边 —— RDP 依赖 TCP 的 FIN 判定流结束，这一步不能省。

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use anyhow::Result;
use rustp2p_quic::{Endpoint, Identity, PeerId};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{broadcast, mpsc, oneshot, Notify};

use crate::{
    pathinfo::spawn_transport_reporter,
    transport::{
        AcceptedStream, AsyncStream, PathState, PeerRef, TransportEndpoint, TransportEvent,
        TransportKind,
    },
};

/// 事件广播通道的容量。
const EVENT_CHANNEL_CAPACITY: usize = 32;

/// 写命令通道的容量。
///
/// 容量小是为了尽快把背压传回上层：quinn 的流控窗口满时，
/// 后台任务会卡在 `write_all` 上，channel 随之填满。
const WRITE_CHANNEL_CAPACITY: usize = 64;

/// 读通道的容量。
const READ_CHANNEL_CAPACITY: usize = 8;

/// 后台读任务每次读取的块大小。
const READ_CHUNK: usize = 16 * 1024;

/// 路径状态的轮询间隔。
const PATH_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// 等待对端被 bootstrap 发现的上限。
const PEER_DISCOVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// rustp2p 传输端点的配置。
#[derive(Debug, Clone)]
pub struct Rustp2pOptions {
    /// 本端 peer id（任意字符串）。
    pub peer_id: String,
    /// 证书种子 —— **必须持久化**，否则重启后身份会变。
    pub seed: Vec<u8>,
    /// 本地监听地址。
    pub bind: SocketAddr,
    /// bootstrap 节点地址（公网 VPS 上的 node）。
    pub bootstrap: Vec<SocketAddr>,
    /// STUN 服务器列表。
    pub stun_servers: Vec<String>,
    /// 辅助打洞 socket 数量 —— 对称 NAT 下必须 > 0。
    pub max_assistant_sockets: usize,
    /// 允许参与打洞的 peer 白名单；`None` 表示不限制。
    pub punch_whitelist: Option<Vec<String>>,
    /// 允许接入的 peer id 白名单；空表示不限制。
    ///
    /// **注意这只是字符串比对，不是身份认证** —— rustp2p 的 peer id 是
    /// 应用层任意字符串，证书校验又被降级为跳过。所以它挡不住有意伪造，
    /// 只挡「手滑连错机器」。见设计文档 §9.4。
    pub allow_list: Vec<String>,
}

impl Default for Rustp2pOptions {
    fn default() -> Self {
        Self {
            peer_id: "irt-node".to_string(),
            seed: b"irt-node-seed".to_vec(),
            bind: "0.0.0.0:0".parse().expect("固定地址可解析"),
            bootstrap: Vec::new(),
            stun_servers: Vec::new(),
            max_assistant_sockets: 4,
            punch_whitelist: None,
            allow_list: Vec::new(),
        }
    }
}

/// rustp2p 传输端点。
pub struct Rustp2pTransport {
    /// 底层 rustp2p 端点。
    endpoint: Endpoint,
    /// 路径事件广播通道。
    events: broadcast::Sender<TransportEvent>,
    /// 当前路径状态。
    state: Arc<Mutex<PathState>>,
    /// server 侧的入站流队列。
    incoming: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Result<AcceptedStream>>>>,
    /// 关注的 peer（路径轮询用）。
    ///
    /// 用 `Arc<Mutex<..>>` 而不是普通 Vec —— server 侧在收到入站流时
    /// 会动态加入新的对端，轮询任务必须能看见。
    watched: Arc<Mutex<Vec<PeerId>>>,
}

impl Rustp2pTransport {
    /// 按配置建立一个 rustp2p 端点。
    ///
    /// `watched` 是需要持续观察路径的 peer 列表：
    /// client 侧是远端，server 侧由 [`Self::watch_peer`] 动态加入。
    pub async fn build(
        opts: &Rustp2pOptions,
        watched: Vec<PeerId>,
        tag: &str,
    ) -> Result<Arc<Self>> {
        let identity = Identity::new(opts.peer_id.clone(), &opts.seed)
            .map_err(|e| anyhow::anyhow!("创建 rustp2p 身份失败: {e}"))?;

        let mut builder = Endpoint::builder()
            .identity(identity)
            .bind(opts.bind)
            .max_assistant_sockets(opts.max_assistant_sockets);

        if !opts.bootstrap.is_empty() {
            builder = builder.bootstrap(opts.bootstrap.clone());
        }
        if !opts.stun_servers.is_empty() {
            builder = builder.stun_servers(opts.stun_servers.clone());
        }
        if let Some(list) = &opts.punch_whitelist {
            builder = builder.punch_whitelist(Some(list.iter().map(PeerId::new).collect()));
        }

        let endpoint = builder
            .build()
            .await
            .map_err(|e| anyhow::anyhow!("绑定 rustp2p 端点失败: {e}"))?;

        let (events, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let (tx, rx) = mpsc::unbounded_channel();

        let transport = Arc::new(Self {
            endpoint: endpoint.clone(),
            events: events.clone(),
            state: Arc::new(Mutex::new(PathState::Connecting)),
            incoming: Arc::new(tokio::sync::Mutex::new(rx)),
            watched: Arc::new(Mutex::new(watched)),
        });

        transport.spawn_accept_loop(tx, opts.allow_list.clone());
        transport.spawn_path_poller();
        // 路径报告由适配器内部统一负责（iroh 适配器也是这么做的），
        // 调用方不需要、也不应该再起一份。
        spawn_transport_reporter(transport.as_ref(), tag);
        Ok(transport)
    }

    /// 关注一个 peer 的路径状态（server 侧在收到入站流时调用）。
    pub fn watch_peer(&self, peer: PeerId) {
        let mut watched = self.watched.lock().unwrap();
        if !watched.contains(&peer) {
            watched.push(peer);
        }
    }

    /// 本端监听地址。
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// 当前的 NAT 观测结果。
    pub fn nat_info(&self) -> rustp2p_quic::NatInfo {
        self.endpoint.nat_info()
    }

    /// 已知的 peer 列表。
    pub fn known_peers(&self) -> Vec<PeerId> {
        self.endpoint
            .known_peers()
            .into_iter()
            .map(|p| p.peer_id)
            .collect()
    }

    /// 后台任务：接受入站双向流。
    fn spawn_accept_loop(
        self: &Arc<Self>,
        tx: mpsc::UnboundedSender<Result<AcceptedStream>>,
        allow_list: Vec<String>,
    ) {
        let endpoint = self.endpoint.clone();
        let watched = self.watched.clone();
        tokio::spawn(async move {
            loop {
                let incoming = match endpoint.accept_bi().await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!("接受入站双向流失败: {e}");
                        // 端点关闭时 accept_bi 会一直出错 —— 退避后重试，避免空转。
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        continue;
                    }
                };
                let peer = incoming.peer_id.clone();
                if !allow_list.is_empty() && !allow_list.iter().any(|a| a == peer.as_str()) {
                    // 只是字符串比对，不是认证（见 Rustp2pOptions::allow_list 的说明）。
                    tracing::warn!("peer {peer} 不在白名单内，拒绝接入");
                    continue;
                }
                tracing::info!("收到来自 {peer} 的双向流");
                // 把入站对端加入「被关注」列表 —— 路径报告只关心它。
                {
                    let mut w = watched.lock().unwrap();
                    if !w.contains(&peer) {
                        w.push(peer.clone());
                    }
                }
                let stream = Rustp2pStream::new(incoming.send, incoming.recv);
                if tx
                    .send(Ok(AcceptedStream {
                        peer: PeerRef::Rustp2p(peer.as_str().to_string()),
                        stream: Box::new(stream),
                    }))
                    .is_err()
                {
                    break;
                }
            }
        });
    }

    /// 后台任务：轮询路径状态并推到广播通道。
    ///
    /// rustp2p-quic 的 `link_mode()` / `link_info()` 是**同步查询**，
    /// 没有订阅接口 —— 所以只能轮询（1 秒一次，足够及时）。
    fn spawn_path_poller(self: &Arc<Self>) {
        let endpoint = self.endpoint.clone();
        let events = self.events.clone();
        let state = self.state.clone();
        let watched = self.watched.clone();

        tokio::spawn(async move {
            // 上一次的状态：(peer, 路径类型, 远端标识)。
            let mut last: Option<(PeerId, PathKind, String)> = None;
            loop {
                tokio::time::sleep(PATH_POLL_INTERVAL).await;

                // **只报告被关注的 peer**。
                //
                // 不能把 known_peers 全都算进来 —— 那会把 bootstrap 节点、
                // 其它无关 peer 的路径也打印出来，淹没真正的对端状态。
                // server 侧的对端在收到入站流时由 `watch_peer` 动态加入。
                let peers = watched.lock().unwrap().clone();
                if peers.is_empty() {
                    continue;
                }

                for peer in &peers {
                    let Some(info) = endpoint.link_info(peer.clone()) else {
                        continue;
                    };
                    let routes = endpoint.routes(peer.clone());
                    let current = match info.mode {
                        rustp2p_quic::LinkMode::Direct => PathState::Direct {
                            remote: routes
                                .first()
                                .map(|r| r.route_key().peer_addr().to_string())
                                .unwrap_or_else(|| peer.as_str().to_string()),
                            rtt: routes
                                .first()
                                .and_then(|r| r.rtt())
                                .map(|ms| Duration::from_millis(ms as u64)),
                        },
                        rustp2p_quic::LinkMode::Relay => PathState::Relay {
                            relay: routes
                                .first()
                                .map(|r| r.route_key().peer_addr().to_string())
                                .unwrap_or_else(|| "中继".to_string()),
                            rtt: routes
                                .first()
                                .and_then(|r| r.rtt())
                                .map(|ms| Duration::from_millis(ms as u64)),
                        },
                    };
                    // 去重时**忽略 rtt** —— RTT 每秒都在微变，
                    // 拿它做判据会疯狂刷屏。
                    let changed = match last.as_ref() {
                        Some((p, k, r)) => p != peer || k != &current_kind(&current) || r != &current_remote(&current),
                        None => true,
                    };
                    if changed {
                        last = Some((
                            peer.clone(),
                            current_kind(&current),
                            current_remote(&current),
                        ));
                        *state.lock().unwrap() = current.clone();
                        let _ = events.send(crate::transport::to_event(&current));
                    }
                }
            }
        });
    }
}

use std::time::Duration;

use crate::pathinfo::PathKind;

/// 取路径状态里的「路径类型」。
fn current_kind(state: &PathState) -> PathKind {
    match state {
        PathState::Direct { .. } => PathKind::Direct,
        PathState::Relay { .. } => PathKind::Relay,
        _ => PathKind::Relay,
    }
}

/// 取路径状态里的「远端标识」。
fn current_remote(state: &PathState) -> String {
    state.remote().unwrap_or_default().to_string()
}

#[async_trait::async_trait]
impl TransportEndpoint for Rustp2pTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Rustp2p
    }

    fn local_id(&self) -> String {
        self.endpoint.peer_id().as_str().to_string()
    }

    async fn open_stream(&self, peer: &PeerRef) -> Result<Box<dyn AsyncStream>> {
        let PeerRef::Rustp2p(id) = peer else {
            anyhow::bail!("rustp2p 后端只能连接 rustp2p 类型的对端标识");
        };
        let peer_id = PeerId::new(id.clone());

        // **必须先等对端出现在已知列表里**。
        //
        // rustp2p 的 `open_bi` 内部是「连不上就重试两次」，而每次重试都会
        // 等路由建立 —— 对端还没被 bootstrap 的 peer 列表发现时，
        // 路由根本不存在，于是这一步会一直挂着，既不报错也不推进。
        //
        // 对端的出现靠 bootstrap 交换 peer 列表，通常几秒内完成。
        let deadline = std::time::Instant::now() + PEER_DISCOVERY_TIMEOUT;
        while !self.endpoint.known_peers().iter().any(|p| p.peer_id == peer_id) {
            if std::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "等待对端 {id} 出现超时（{} 秒）—— 检查 bootstrap 是否可达、                     两端是否连的是同一个 bootstrap",
                    PEER_DISCOVERY_TIMEOUT.as_secs()
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        tracing::debug!("对端 {id} 已出现，打开双向流");

        let (send, recv) = self
            .endpoint
            .open_bi(peer_id)
            .await
            .map_err(|e| anyhow::anyhow!("打开到 {id} 的双向流失败: {e}"))?;
        Ok(Box::new(Rustp2pStream::new(send, recv)))
    }

    async fn accept_stream(&self) -> Result<AcceptedStream> {
        let mut rx = self.incoming.lock().await;
        match rx.recv().await {
            Some(Ok(s)) => Ok(s),
            Some(Err(e)) => Err(e),
            None => anyhow::bail!("rustp2p 端点已关闭"),
        }
    }

    fn path_state(&self) -> PathState {
        self.state.lock().unwrap().clone()
    }

    fn subscribe(&self) -> broadcast::Receiver<TransportEvent> {
        self.events.subscribe()
    }

    async fn close(&self) {
        self.endpoint.close().await;
    }
}

/// 等待中的写半边关闭 future。
type PendingFinish = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

/// 写侧命令。
enum WriteCmd {
    /// 追加数据（后台任务按序写出）。
    Data(Vec<u8>),
    /// 结束写半边。
    Finish(oneshot::Sender<io::Result<()>>),
}

/// rustp2p 可靠流 ↔ Tokio 字节流的适配器。
pub struct Rustp2pStream {
    /// 写命令发送端。
    write_tx: mpsc::Sender<WriteCmd>,
    /// **还没被底层接受**的数据。
    ///
    /// `AsyncWrite` 的契约要求：`poll_write` 返回 `Pending` 时**绝不能**已经
    /// 接受了数据 —— 否则上层会带着一份「更长的 buf」重试（tokio 的 `copy`
    /// 在 `poll_write` 挂起期间会继续 `poll_read` 往 buf 里追加），
    /// 旧数据就会被重复发送。
    ///
    /// 所以 channel 满时，数据先留在这里，等有空位再送出去。
    pending_data: Vec<u8>,
    /// 「写通道有空位了」的通知（后台任务消费时唤醒等待者）。
    write_space: Arc<Notify>,
    /// 等待写通道空位的 future。
    write_space_waiter: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    /// 等待中的写半边关闭 future。
    finish_pending: Option<PendingFinish>,
    /// 读数据接收端。
    read_rx: mpsc::Receiver<io::Result<Vec<u8>>>,
    /// 已收到但还没被上层取走的读数据。
    read_buf: Vec<u8>,
    /// 读缓冲的已消费位置。
    read_pos: usize,
    /// 读侧是否已结束（对端 EOF 或出错）。
    read_done: bool,
}

impl Rustp2pStream {
    /// 组装一条流：把读写两半交给后台任务。
    pub fn new(
        send: rustp2p_quic::ReliableSendStream,
        recv: rustp2p_quic::ReliableRecvStream,
    ) -> Self {
        let (write_tx, mut write_rx) = mpsc::channel::<WriteCmd>(WRITE_CHANNEL_CAPACITY);
        let (read_tx, read_rx) = mpsc::channel::<io::Result<Vec<u8>>>(READ_CHANNEL_CAPACITY);
        let write_space = Arc::new(Notify::new());
        let write_space2 = Arc::clone(&write_space);

        // 写任务：按序把数据交给 QUIC。
        tokio::spawn(async move {
            let mut send = send;
            while let Some(cmd) = write_rx.recv().await {
                // 消费了一个命令 ⇒ 通道里有空位了 ⇒ 唤醒可能挂着的写者。
                write_space2.notify_waiters();
                match cmd {
                    WriteCmd::Data(data) => {
                        if let Err(e) = send.write_all(&data).await {
                            tracing::warn!("rustp2p 写入失败: {e}");
                            break;
                        }
                    }
                    WriteCmd::Finish(tx) => {
                        let r = send.finish();
                        let _ = tx.send(r);
                        break;
                    }
                }
            }
        });

        // 读任务：循环读，把每个 chunk 送出去。
        tokio::spawn(async move {
            let mut recv = recv;
            let mut buf = vec![0u8; READ_CHUNK];
            loop {
                match recv.read(&mut buf).await {
                    Ok(Some(n)) => {
                        if read_tx.send(Ok(buf[..n].to_vec())).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        let _ = read_tx.send(Err(e)).await;
                        break;
                    }
                }
            }
        });

        Self {
            write_tx,
            pending_data: Vec::new(),
            write_space,
            write_space_waiter: None,
            finish_pending: None,
            read_rx,
            read_buf: Vec::new(),
            read_pos: 0,
            read_done: false,
        }
    }
}

impl Rustp2pStream {
    /// 等写通道腾出空位。
    ///
    /// 后台任务每消费一个命令就会 `notify_waiters()`。
    fn wait_for_write_space(&mut self, cx: &mut Context<'_>) {
        let notify = Arc::clone(&self.write_space);
        let mut waiter = Box::pin(async move { notify.notified().await });
        if waiter.as_mut().poll(cx).is_pending() {
            self.write_space_waiter = Some(waiter);
        }
    }
}

impl AsyncRead for Rustp2pStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.read_pos < this.read_buf.len() {
                let avail = this.read_buf.len() - this.read_pos;
                let n = avail.min(buf.remaining());
                buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + n]);
                this.read_pos += n;
                if this.read_pos >= this.read_buf.len() {
                    this.read_buf.clear();
                    this.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.read_done {
                // EOF：不再往 buf 里放字节。
                return Poll::Ready(Ok(()));
            }
            match this.read_rx.poll_recv(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    this.read_buf = data;
                    this.read_pos = 0;
                }
                Poll::Ready(Some(Err(e))) => {
                    this.read_done = true;
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(None) => {
                    this.read_done = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for Rustp2pStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // 1) 先把上次没被接受的数据送出去。
        if !this.pending_data.is_empty() {
            let data = std::mem::take(&mut this.pending_data);
            match this.write_tx.try_send(WriteCmd::Data(data)) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(cmd)) => {
                    let WriteCmd::Data(data) = cmd else {
                        return Poll::Ready(Err(broken_pipe()));
                    };
                    this.pending_data = data;
                    this.wait_for_write_space(cx);
                    return Poll::Pending;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Poll::Ready(Err(broken_pipe()));
                }
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // 2) 发送新数据。
        //
        // 用 `try_send` 而不是 `send().await`：`send` 的 future 一旦被 poll
        // 就可能把数据**放进队列**，此时若返回 `Pending`，上层会以为数据没被
        // 接受、用更大的 buf 重试 ⇒ 旧数据被重复发送。
        //
        // `try_send` 失败 ⇒ 数据**一定**没被接受 ⇒ 返回 `Pending` 是诚实的。
        let n = buf.len();
        match this.write_tx.try_send(WriteCmd::Data(buf.to_vec())) {
            Ok(()) => Poll::Ready(Ok(n)),
            Err(mpsc::error::TrySendError::Full(cmd)) => {
                    let WriteCmd::Data(data) = cmd else {
                        return Poll::Ready(Err(broken_pipe()));
                    };
                this.pending_data = data;
                this.wait_for_write_space(cx);
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(broken_pipe()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // quinn 没有用户态 flush：`write_all` 已经把数据交给 QUIC 发送缓冲。
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(fut) = this.finish_pending.as_mut() {
            return fut.as_mut().poll(cx);
        }
        let (tx, rx) = oneshot::channel();
        let cmd = WriteCmd::Finish(tx);
        let sender = this.write_tx.clone();
        let fut = Box::pin(async move {
            if sender.send(cmd).await.is_err() {
                return Err(broken_pipe());
            }
            // 后台任务回复 finish 的结果；拿不到就当作成功（流已经关了）。
            match rx.await {
                Ok(r) => r,
                Err(_) => Ok(()),
            }
        });
        this.finish_pending = Some(fut);
        this.finish_pending.as_mut().unwrap().as_mut().poll(cx)
    }
}

/// 连接已断。
fn broken_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "rustp2p 流已关闭")
}
