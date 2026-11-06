//! `irt diag` —— 网络体检。

use anyhow::Result;

use crate::cli::DiagArgs;

/// 运行网络体检。
pub async fn run(_args: DiagArgs) -> Result<()> {
    println!("irt diag —— 尚未实现");
    Ok(())
}
