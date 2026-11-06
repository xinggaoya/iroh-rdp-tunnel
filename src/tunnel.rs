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

    // 一侧读到 EOF 时只半关闭对端的写半边，另一侧继续 —— 这是 TCP 的半关闭语义，
    // RDP 依赖它来判定流结束。
    // 但**一侧出错**时不能干等另一侧：连接已经废了，另一侧会一直挂着。
    let mut up_fut = Box::pin(async {
        let r = tokio::io::copy(&mut a_read, &mut b_write).await;
        let _ = b_write.shutdown().await;
        r.map(|_| ())
    });
    let mut down_fut = Box::pin(async {
        let r = tokio::io::copy(&mut b_read, &mut a_write).await;
        let _ = a_write.shutdown().await;
        r.map(|_| ())
    });

    let mut up_done = false;
    let mut down_done = false;
    loop {
        tokio::select! {
            r = &mut up_fut, if !up_done => {
                up_done = true;
                r?;
                if down_done { return Ok(()); }
            }
            r = &mut down_fut, if !down_done => {
                down_done = true;
                r?;
                if up_done { return Ok(()); }
            }
        }
    }
}

/// server 侧：传输层流 ↔ 本地 TCP。
///
/// 用传输层的 [`crate::transport::AsyncStream`] 而不是 iroh 的 QUIC 流，
/// 这样 server 代码与具体后端解耦。
pub async fn bridge_stream_to_tcp(
    stream: Box<dyn crate::transport::AsyncStream>,
    tcp: tokio::net::TcpStream,
) -> io::Result<()> {
    bridge(stream, tcp).await
}

/// client 侧：本地 TCP ↔ 传输层流。
pub async fn bridge_tcp_to_stream(
    local: tokio::net::TcpStream,
    stream: Box<dyn crate::transport::AsyncStream>,
) -> io::Result<()> {
    bridge(local, stream).await
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
