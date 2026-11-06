//! rustp2p-quic 后端的端到端集成测试。
//!
//! 进程内起三个 rustp2p 节点：
//!
//! ```text
//!   bootstrap（兼中继）        server（被控端）        client（控制端）
//!        127.0.0.1:随机端口  ◄── 发现 ──►        127.0.0.1:随机端口
//! ```
//!
//! **不依赖外网**：bootstrap 在本机回环上，STUN 服务器留空
//! （回环不需要 NAT 观测就能直连）。
//!
//! 覆盖：
//! 1. 字节流双向透传与完整性；
//! 2. 半关闭（`shutdown` → 对端读到 EOF）—— RDP 依赖 TCP 的 FIN 判定流结束；
//! 3. 路径状态能判定出直连。

use std::time::Duration;

use iroh_rdp_tunnel::transport::{
    PeerRef, TransportEndpoint,
    rustp2p::{Rustp2pOptions, Rustp2pTransport},
};
use rustp2p_quic::PeerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 等待 peer 出现在已知列表里。
async fn wait_for_peer(transport: &Rustp2pTransport, peer: &str) {
    let want = PeerId::new(peer);
    for _ in 0..60 {
        if transport.known_peers().contains(&want) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!(
        "peer {peer} 未在 30 秒内被发现，已知: {:?}",
        transport
            .known_peers()
            .iter()
            .map(|p| p.as_str().to_string())
            .collect::<Vec<_>>()
    );
}

/// 起一个节点。
async fn spawn_node(
    peer_id: &str,
    bootstrap: Vec<std::net::SocketAddr>,
    watched: Vec<PeerId>,
) -> std::sync::Arc<Rustp2pTransport> {
    Rustp2pTransport::build(
        &Rustp2pOptions {
            peer_id: peer_id.to_string(),
            seed: format!("{peer_id}-seed").into_bytes(),
            bind: "127.0.0.1:0".parse().unwrap(),
            bootstrap,
            stun_servers: Vec::new(),
            max_assistant_sockets: 2,
            punch_whitelist: None,
            allow_list: Vec::new(),
        },
        watched,
        "test",
    )
    .await
    .expect("建立 rustp2p 节点失败")
}

/// 起一整套三节点拓扑，返回 (server, client)。
async fn spawn_topology() -> (
    std::sync::Arc<Rustp2pTransport>,
    std::sync::Arc<Rustp2pTransport>,
) {
    let bootstrap = spawn_node("bootstrap", vec![], vec![]).await;
    let bootstrap_addr = bootstrap.local_addr().expect("bootstrap 应有监听地址");

    let server = spawn_node("server", vec![bootstrap_addr], vec![]).await;
    let client = spawn_node(
        "client",
        vec![bootstrap_addr],
        vec![PeerId::new("server")],
    )
    .await;

    wait_for_peer(&server, "client").await;
    wait_for_peer(&client, "server").await;

    (server, client)
}

#[tokio::test]
async fn rustp2p_tunnel_roundtrips_bytes() {
    let (server, client) = spawn_topology().await;

    // server 侧：边读边原样回写，直到对端半关闭。
    let server_task = tokio::spawn(async move {
        let accepted = server.accept_stream().await.expect("应接受到入站流");
        let mut stream = accepted.stream;
        let mut buf = vec![0u8; 16 * 1024];
        let mut total = 0usize;
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
            stream.write_all(&buf[..n]).await.unwrap();
        }
        stream.shutdown().await.unwrap();
        total
    });

    // client 侧：开流、发数据、半关闭写侧，再收回显直到 EOF。
    let mut stream = client
        .open_stream(&PeerRef::Rustp2p("server".to_string()))
        .await
        .expect("应能打开双向流");

    let payload: Vec<u8> = (0..32 * 1024).map(|i| (i % 251) as u8).collect();
    let expect_len = payload.len();
    stream.write_all(&payload).await.unwrap();
    // 半关闭写侧 —— 对端应看到 EOF，而本端的读半边仍然可用。
    stream.shutdown().await.unwrap();

    let mut got = Vec::new();
    stream.read_to_end(&mut got).await.unwrap();

    assert_eq!(got.len(), expect_len, "字节数必须一致");
    assert_eq!(got, payload, "字节必须逐字节一致");

    let server_got = server_task.await.unwrap();
    assert_eq!(server_got, expect_len, "server 侧应收到的字节数一致");
}

#[tokio::test]
async fn rustp2p_half_close_propagates_eof() {
    let (server, client) = spawn_topology().await;

    // server 侧：读完就 finish 写半边，让 client 看到 EOF。
    let server_task = tokio::spawn(async move {
        let accepted = server.accept_stream().await.expect("应接受到入站流");
        let mut stream = accepted.stream;
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        assert!(n > 0, "应读到数据");
        stream.shutdown().await.unwrap();
        n
    });

    let mut stream = client
        .open_stream(&PeerRef::Rustp2p("server".to_string()))
        .await
        .expect("应能打开双向流");

    stream.write_all(b"bye").await.unwrap();
    // 半关闭后，client 读侧应收到 EOF（读到 0 字节）。
    let mut rest = Vec::new();
    let n = stream.read_to_end(&mut rest).await.unwrap();
    assert_eq!(n, 0, "对端 finish 后不应再有数据");
    assert!(rest.is_empty());

    assert_eq!(server_task.await.unwrap(), 3);
}

#[tokio::test]
async fn rustp2p_reports_direct_path_on_loopback() {
    let (_server, client) = spawn_topology().await;

    // 回环上必然是直连（没有 NAT）。
    let mut direct = false;
    for _ in 0..30 {
        let state = client.path_state();
        if state.is_direct() {
            direct = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(direct, "回环上应当判定为直连，实际: {:?}", client.path_state());
}

/// 大流量传输 —— **专门盯住 `poll_write` 的契约**。
///
/// 曾经的 bug：`poll_write` 返回 `Pending` 时数据其实已经进了队列，
/// 上层（tokio 的 `copy`）会带着一份**更长的 buf** 重试 ⇒ 旧数据被重复发送。
/// 小包（≤ 32 KB）不一定触发，1 MB 必现。
#[tokio::test]
async fn rustp2p_tunnel_roundtrips_large_payload() {
    let (server, client) = spawn_topology().await;

    let server_task = tokio::spawn(async move {
        let accepted = server.accept_stream().await.expect("应接受到入站流");
        let mut stream = accepted.stream;
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0usize;
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
            stream.write_all(&buf[..n]).await.unwrap();
        }
        stream.shutdown().await.unwrap();
        total
    });

    let mut stream = client
        .open_stream(&PeerRef::Rustp2p("server".to_string()))
        .await
        .expect("应能打开双向流");

    let payload: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
    let expect_len = payload.len();
    stream.write_all(&payload).await.unwrap();
    stream.shutdown().await.unwrap();

    let mut got = Vec::new();
    stream.read_to_end(&mut got).await.unwrap();

    assert_eq!(
        got.len(),
        expect_len,
        "字节数必须一致 —— 多出来说明 poll_write 违反契约导致重复"
    );
    assert_eq!(got, payload, "字节必须逐字节一致");
    assert_eq!(server_task.await.unwrap(), expect_len);
}

/// 背压路径 —— **专门盯住 `pending_data` 分支**。
///
/// 写通道容量有限（64 × 8 KB ≈ 512 KB）。对端**慢读**时，通道必然被填满，
/// `poll_write` 就要走 `pending_data` + `Notify` 那条路。
///
/// 本地回环太快，1 MB 往往填不满通道 —— 所以这里让对端先「睡着」3 秒，
/// 强制把背压路径逼出来。
#[tokio::test]
async fn rustp2p_slow_reader_exercises_backpressure() {
    let (server, client) = spawn_topology().await;

    let server_task = tokio::spawn(async move {
        let accepted = server.accept_stream().await.expect("应接受到入站流");
        let mut stream = accepted.stream;
        // 先不读 —— 让对端的写通道被填满。
        tokio::time::sleep(Duration::from_secs(3)).await;
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0usize;
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
            stream.write_all(&buf[..n]).await.unwrap();
        }
        stream.shutdown().await.unwrap();
        total
    });

    let mut stream = client
        .open_stream(&PeerRef::Rustp2p("server".to_string()))
        .await
        .expect("应能打开双向流");

    let payload: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let expect_len = payload.len();
    stream.write_all(&payload).await.unwrap();
    stream.shutdown().await.unwrap();

    let mut got = Vec::new();
    stream.read_to_end(&mut got).await.unwrap();

    assert_eq!(
        got.len(),
        expect_len,
        "字节数必须一致 —— 背压路径上若有重复，这里会炸"
    );
    assert_eq!(got, payload, "字节必须逐字节一致");
    assert_eq!(server_task.await.unwrap(), expect_len);
}

/// 并发开流到**同一个对端** —— 专门盯住 rustp2p-quic 的虚拟地址竞态。
///
/// `rustp2p-quic` 的 `open_bi` 内部：握手失败会把 `virtual_by_peer[peer]` 与
/// `virtual_by_addr[addr]` **一起删掉**，但缓存里的 `connections[peer]` 仍指向
/// 旧地址。下一次 `register_virtual_peer` 会分配**新**地址，而
/// `connection_to_at` 命中缓存返回**旧**连接 ⇒ quinn 往一个已注销的地址发包 ⇒
/// `unknown synthetic QUIC destination`，且**永远恢复不了**。
///
/// 触发条件是**并发** `open_bi`（每个本地 TCP 连接都会开一个流）。
#[tokio::test]
async fn rustp2p_concurrent_streams_to_same_peer() {
    let (server, client) = spawn_topology().await;

    // server 侧：接受多条流并回显。
    let server_task = tokio::spawn(async move {
        for _ in 0..8 {
            let accepted = match server.accept_stream().await {
                Ok(s) => s,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut stream = accepted.stream;
                let mut buf = vec![0u8; 16 * 1024];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                let _ = stream.shutdown().await;
            });
        }
    });

    // client 侧：**同时**开 8 条流到同一个对端。
    let payload: Vec<u8> = (0..8 * 1024).map(|i| (i % 251) as u8).collect();
    let expect_len = payload.len();
    let peer = PeerRef::Rustp2p("server".to_string());

    let mut handles = Vec::new();
    for _ in 0..8 {
        let client = client.clone();
        let peer = peer.clone();
        let payload = payload.clone();
        handles.push(tokio::spawn(async move {
            let mut stream = client.open_stream(&peer).await.expect("应能打开双向流");
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut got = Vec::new();
            stream.read_to_end(&mut got).await.unwrap();
            got
        }));
    }

    for h in handles {
        let got = h.await.expect("并发开流的任务不应 panic");
        assert_eq!(
            got.len(),
            expect_len,
            "并发开流时字节数必须一致 —— 少字节说明虚拟地址竞态导致流被打断"
        );
        assert_eq!(got, payload, "字节必须逐字节一致");
    }
    server_task.abort();
}
