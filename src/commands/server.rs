//! `irt server` —— 在被控的 Windows 机器上运行。

use anyhow::Result;

use crate::config::ServerConfig;

/// 运行被控端。
pub async fn run(_cfg: ServerConfig) -> Result<()> {
    println!("irt server —— 尚未实现");
    Ok(())
}
