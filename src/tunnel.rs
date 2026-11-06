//! TCP ↔ QUIC stream 双向桥接。
//!
//! 桥接核心 `bridge` 写成泛型（只要求 `AsyncRead + AsyncWrite`），
//! 这样可以用 `tokio::io::duplex` 在单元测试里直接验证字节双向透传与半关闭语义，
//! 而不必真的跑一条 QUIC 连接。

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use iroh::endpoint::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

/// 一端双向字节流。
pub trait BytePipe: AsyncRead + AsyncWrite + Unpin {}

impl<T: AsyncRead + AsyncWrite + Unpin> BytePipe for T {}

/// 把 iroh 的 QUIC 发送流与接收流组合成一个双向字节流。
pub struct QuicStream {
    send: SendStream,
    recv: RecvStream,
}

impl QuicStream {
    /// 组装一条 QUIC 双向流。
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // 显式调用 tokio 的 trait 方法：SendStream 自带一个 futures_io 的同名固有方法，
        // 直接 `send.poll_write(..)` 会解析到那个（错误类型是 WriteError）。
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
    }
}

/// 在两端之间做双向字节转发。
///
/// 某一方向读到 EOF 后会**半关闭**对端的写半边，让对端也能看到 EOF；
/// RDP 协议依赖 TCP 的 FIN 来判定流结束，这一步不能省。
pub async fn bridge<P1, P2>(a: P1, b: P2) -> io::Result<()>
where
    P1: BytePipe,
    P2: BytePipe,
{
    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);

    let up = async {
        let r = tokio::io::copy(&mut a_read, &mut b_write).await;
        let _ = b_write.shutdown().await;
        r
    };
    let down = async {
        let r = tokio::io::copy(&mut b_read, &mut a_write).await;
        let _ = a_write.shutdown().await;
        r
    };

    let (r1, r2) = tokio::join!(up, down);
    match (r1, r2) {
        (Ok(_), Ok(_)) => Ok(()),
        (Err(e), _) | (_, Err(e)) => Err(e),
    }
}

/// server 侧：QUIC 流 ↔ 本地 TCP。
pub async fn bridge_quic_to_tcp(
    send: SendStream,
    recv: RecvStream,
    tcp: tokio::net::TcpStream,
) -> io::Result<()> {
    bridge(QuicStream::new(send, recv), tcp).await
}

/// client 侧：本地 TCP ↔ QUIC 流。
pub async fn bridge_tcp_to_quic(
    local: tokio::net::TcpStream,
    send: SendStream,
    recv: RecvStream,
) -> io::Result<()> {
    bridge(local, QuicStream::new(send, recv)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 读超时：桥接若忘了半关闭，这里会超时失败，而不是把测试挂死。
    const READ_TIMEOUT: Duration = Duration::from_secs(5);

    /// 造一对「测试端 ↔ 桥接端」的单向管道。
    fn pipe(cap: usize) -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        tokio::io::duplex(cap)
    }

    #[tokio::test]
    async fn bridge_forwards_bytes_in_both_directions() {
        let (mut a_writer, a_bridge) = pipe(64 * 1024);
        let (b_bridge, mut b_reader) = pipe(64 * 1024);
        let handle = tokio::spawn(async move { bridge(a_bridge, b_bridge).await });

        a_writer.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tokio::time::timeout(READ_TIMEOUT, b_reader.read_exact(&mut buf))
            .await
            .expect("读取超时")
            .unwrap();
        assert_eq!(&buf, b"ping");

        b_reader.write_all(b"pong").await.unwrap();
        let mut buf2 = [0u8; 4];
        tokio::time::timeout(READ_TIMEOUT, a_writer.read_exact(&mut buf2))
            .await
            .expect("读取超时")
            .unwrap();
        assert_eq!(&buf2, b"pong");

        drop(a_writer);
        drop(b_reader);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn bridge_propagates_half_close() {
        let (mut a_writer, a_bridge) = pipe(64 * 1024);
        let (b_bridge, mut b_reader) = pipe(64 * 1024);
        let handle = tokio::spawn(async move { bridge(a_bridge, b_bridge).await });

        a_writer.write_all(b"bye").await.unwrap();
        a_writer.shutdown().await.unwrap();

        // 先读到数据，再读到 EOF
        let mut buf = Vec::new();
        let n = tokio::time::timeout(READ_TIMEOUT, b_reader.read_to_end(&mut buf))
            .await
            .expect("等待 EOF 超时：桥接未把半关闭传给对端")
            .unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf, b"bye");

        drop(b_reader);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn bridge_moves_large_payloads_without_corruption() {
        let (mut a_writer, a_bridge) = pipe(1024 * 1024);
        let (b_bridge, mut b_reader) = pipe(1024 * 1024);
        let handle = tokio::spawn(async move { bridge(a_bridge, b_bridge).await });

        let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
        let expect = payload.clone();
        let writer = tokio::spawn(async move {
            a_writer.write_all(&payload).await.unwrap();
            a_writer.shutdown().await.unwrap();
        });

        let mut got = Vec::new();
        tokio::time::timeout(READ_TIMEOUT, b_reader.read_to_end(&mut got))
            .await
            .expect("读取超时")
            .unwrap();
        writer.await.unwrap();

        assert_eq!(got.len(), expect.len());
        assert_eq!(got, expect, "字节必须逐字节一致");
        drop(b_reader);
        let _ = handle.await;
    }
}
