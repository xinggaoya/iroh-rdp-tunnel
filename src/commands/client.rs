//! `irt client` —— 在控制端运行。

use anyhow::Result;

use crate::config::ClientConfig;

/// 运行控制端。
pub async fn run(_cfg: ClientConfig) -> Result<()> {
    println!("irt client —— 尚未实现");
    Ok(())
}
