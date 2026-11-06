//! 子命令实现。
//!
//! 业务逻辑放在库里而不是 `bin/` 里，集成测试可以直接调用。

pub mod client;
pub mod diag;
pub mod server;
