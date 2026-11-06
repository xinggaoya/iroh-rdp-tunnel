//! iroh-rdp-tunnel —— 基于 iroh 的 Windows RDP 点对点隧道。
//!
//! 库部分只做模块聚合与公共常量再导出；业务逻辑在 [`commands`] 子模块里，
//! 便于集成测试直接调用。

pub mod addrpolicy;
pub mod cli;
pub mod commands;
pub mod config;
pub mod connmgr;
pub mod endpoint;
pub mod keys;
pub mod pathinfo;
pub mod tunnel;

/// QUIC 握手中协商的 ALPN；两端必须完全一致。
pub const ALPN: &[u8] = b"iroh-rdp-tunnel/0";

/// 被控端本机 Windows RDP 服务地址（回环）。
pub const RDP_LOCAL: &str = "127.0.0.1:3389";

/// 控制端本地监听的「假 RDP」地址。
pub const LISTEN_ADDR: &str = "127.0.0.1:13389";

/// 构建标记 —— 启动时打印，方便区分新旧二进制。
pub const BUILD_TAG: &str = "v0.2.0";
