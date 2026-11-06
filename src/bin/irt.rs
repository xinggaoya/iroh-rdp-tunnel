//! `irt` —— 单一入口。所有逻辑在库里，这里只是薄壳。

fn main() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(iroh_rdp_tunnel::cli::run())
}
