//! 端到端集成测试：进程内 relay + 被控端 + 控制端。
//!
//! **不依赖外网**：relay 由 `iroh::test_utils::run_relay_server()` 在进程内启动，
//! 地址发布/解析全部关闭（`Discovery::Disabled`），
//! 客户端直接带着 relay URL 拨号，绕开 DNS。

use std::{collections::BTreeSet, net::SocketAddr, path::PathBuf, time::Duration};

use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey, TransportAddr,
    protocol::Router,
};
use iroh_rdp_tunnel::{
    ALPN,
    addrpolicy::PublishPolicy,
    commands::server::{self, ServerRuntime},
    config::ServerConfig,
    endpoint::{Discovery, EndpointOptions, bind},
    pathinfo,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

/// 起一个「假 RDP」回显服务，返回它的监听地址。
///
/// 隧道两端的字节必须原样穿过：client TCP → QUIC → server TCP → 回显 → 原路返回。
async fn spawn_fake_rdp() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// 临时密钥文件路径。
fn temp_key_file(tag: &str) -> PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("irt-e2e-{tag}-{n}.key"))
}

/// 起一个被控端，返回 (远端地址, 运行时, router)。
async fn start_server(
    relay_url: RelayUrl,
    rdp_target: SocketAddr,
    allow_list: Vec<EndpointId>,
) -> (EndpointAddr, ServerRuntime, Router) {
    let cfg = ServerConfig {
        key_file: temp_key_file("server"),
        rdp_target,
        publish: PublishPolicy::RelayOnly,
        relay_mode: RelayMode::custom([relay_url.clone()]),
        allow_list,
        discovery: Discovery::Disabled,
        ca_tls_config: Some(iroh::tls::CaTlsConfig::insecure_skip_verify()),
    };
    let rt = server::build(&cfg).await.unwrap();
    // 等被控端连上 relay，否则控制端拨过去时 relay 还不认识它。
    tokio::time::timeout(Duration::from_secs(30), rt.endpoint.online())
        .await
        .expect("被控端未能在超时内连上 relay");
    let id = rt.endpoint.id();
    let endpoint = rt.endpoint.clone();
    let router = Router::builder(endpoint).accept(ALPN.to_vec(), rt.handler.clone()).spawn();
    let addr = EndpointAddr {
        id,
        addrs: BTreeSet::from([TransportAddr::Relay(relay_url)]),
    };
    (addr, rt, router)
}

/// 起一个控制端端点。
async fn start_client(relay_url: RelayUrl) -> Endpoint {
    let ep = bind(EndpointOptions {
        secret_key: None,
        relay_mode: RelayMode::custom([relay_url]),
        publish: PublishPolicy::RelayOnly,
        discovery: Discovery::Disabled,
        portmapper: false,
        ca_tls_config: Some(iroh::tls::CaTlsConfig::insecure_skip_verify()),
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(30), ep.online())
        .await
        .expect("控制端未能在超时内连上 relay");
    ep
}

#[tokio::test]
async fn tunnel_roundtrip_preserves_bytes() {
    let (_map, relay_url, _relay) = iroh::test_utils::run_relay_server().await.unwrap();
    let rdp = spawn_fake_rdp().await;
    let (remote, _rt, _router) = start_server(relay_url.clone(), rdp, vec![]).await;
    let client = start_client(relay_url).await;

    let conn = client.connect(remote, ALPN).await.unwrap();

    // 连上之后必须能判定当前走的是直连还是中继。
    let info = pathinfo::describe_path(&conn).expect("连接建立后应能读到当前路径");
    assert!(
        matches!(
            info.kind,
            pathinfo::PathKind::Direct | pathinfo::PathKind::Relay
        ),
        "路径类型必须可判定，实际: {:?}",
        info.kind
    );
    assert!(!info.remote.is_empty(), "路径必须有远端地址");

    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    let expect_len = payload.len();

    // 读与写并发，避免流控窗口打满后互相等待。
    let reader = tokio::spawn(async move {
        let mut got = vec![0u8; expect_len];
        recv.read_exact(&mut got).await.unwrap();
        got
    });
    send.write_all(&payload).await.unwrap();
    let got = reader.await.unwrap();

    assert_eq!(got.len(), expect_len, "字节数必须一致");
    assert_eq!(got, payload, "字节必须逐字节一致");
}

#[tokio::test]
async fn allow_list_rejects_unknown_peer() {
    let (_map, relay_url, _relay) = iroh::test_utils::run_relay_server().await.unwrap();
    let rdp = spawn_fake_rdp().await;

    // 白名单里放一个与客户端无关的 id
    let allowed = SecretKey::generate().public();
    let (remote, _rt, _router) = start_server(relay_url.clone(), rdp, vec![allowed]).await;
    let client = start_client(relay_url).await;

    let outcome = tokio::time::timeout(Duration::from_secs(20), async {
        let conn = client
            .connect(remote, ALPN)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        send.write_all(b"ping")
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut buf = [0u8; 4];
        recv.read_exact(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok::<(), anyhow::Error>(())
    })
    .await;

    // 外层是超时，内层是连接/读写本身的错误；
    // 白名单外的 peer 必须落在**内层错误**上（握手被拒或流被关闭）。
    let inner = outcome.expect("不应超时：连接被拒后应立即失败，而不是干等");
    assert!(
        inner.is_err(),
        "白名单外的 peer 不应当能交换数据（握手或读写必须失败）"
    );
}

#[tokio::test]
async fn allow_list_accepts_listed_peer() {
    let (_map, relay_url, _relay) = iroh::test_utils::run_relay_server().await.unwrap();
    let rdp = spawn_fake_rdp().await;

    let client = start_client(relay_url.clone()).await;
    let client_id = client.id();

    let (remote, _rt, _router) = start_server(relay_url.clone(), rdp, vec![client_id]).await;

    let conn = client.connect(remote, ALPN).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    let reader = tokio::spawn(async move {
        let mut buf = [0u8; 4];
        recv.read_exact(&mut buf).await.unwrap();
        buf
    });
    send.write_all(b"ping").await.unwrap();
    let got = reader.await.unwrap();
    assert_eq!(&got, b"ping");
}
