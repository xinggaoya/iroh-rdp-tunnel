# iroh-rdp-tunnel v0.2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 iroh-rdp-tunnel 在实测网络画像（EIM 映射 + 地址依赖过滤 + 无 UPnP + 无 IPv6）下真正走通 P2P 直连，并把「直连还是中继」变成运行时可见指标。

**Architecture:** 重构为「库 + 单一 `irt` 入口」：`src/lib.rs` 只做模块聚合，`src/cli.rs` 定义 clap 子命令，`src/commands/*` 承载业务逻辑（可被集成测试直接调用），`src/bin/irt.rs` 是 10 行薄壳。核心改动是把 server 的地址发布策略从 `ip_only()` 改回 `relay-only`（iroh 标准模型），让 iroh 原生的 QUIC NAT Traversal 打洞在已建立的连接上完成「双方同时发包」，随后自动迁移到直连路径。

**Tech Stack:** Rust 2021 · iroh 1.0.2 · tokio 1 · clap 4 · portmapper 0.19 · n0-watcher

**Spec:** `DESIGN.md`（仓库根目录，已获用户批准）

## Global Constraints

- Rust edition **2021**（`std::env::set_var` 在此 edition 下是 safe，但**禁止在测试里改进程环境**——环境读取必须走注入式 `EnvSource`）
- `iroh = "1.0"`（`Cargo.lock` 已锁 1.0.2），启用 feature `unstable-net-report`；**禁止**升级到 1.1+（API 未验证）
- 端口常量固定：`RDP_LOCAL = 127.0.0.1:3389`，`LISTEN_ADDR = 127.0.0.1:13389`
- ALPN 固定：`b"iroh-rdp-tunnel/0"`（**不得改动**，改了老客户端全部失联）
- `BUILD_TAG` 固定为 `"v0.2.0"`
- 默认发布策略固定为 `PublishPolicy::RelayOnly`
- 密钥文件默认路径：`%APPDATA%\iroh-rdp-tunnel\server.key`（Windows）/ `~/.config/iroh-rdp-tunnel/server.key`（其它平台）
- 防火墙规则名固定：`iroh-rdp-tunnel (irt UDP inbound)`
- 二进制名固定：`irt`（`src/bin/irt.rs`）
- 旧环境变量 `NO_RELAY` / `FORCE_RELAY` / `FORCE_IPV6` 必须继续生效；从未真正生效的 `FORCE_IPV4_ONLY` 删除
- 单元测试写在各模块内的 `#[cfg(test)] mod tests`；端到端测试写在 `tests/e2e.rs`
- 每个任务结束必须 `cargo test` 通过，且 `cargo build --release` 无警告
- 提交粒度：一个 Task 一次提交，commit message 用中文 + 任务名

## Review Focus

规格隐含、但没有哪条测试会覆盖的五类输入/失效模式：

1. **IPv6 全局地址缺失**（本机只有 `fe80::`）——任何"优先 IPv6"或"必须有 IPv6"的分支都会在这台机器上失败
2. **公网端口 ≠ 本地端口**（EIM 但经过光猫 NAT，映射端口会变）——不能用「本地端口 == 公网端口」推断无 NAT
3. **NAT 过滤是地址依赖**——任何"服务端单方面先发包就能建连"的假设都不成立
4. **UPnP/NAT-PMP/PCP 全不支持**——端口映射探测必须能优雅降级为「未知」而不是报错退出
5. **endpoint id 含 64 位十六进制**——任何按固定长度截断、含大小写假设、或复制粘贴时带空白/换行的处理都要覆盖

---

## File Structure

| 文件 | 责任 |
|---|---|
| `Cargo.toml` | 依赖与 feature 声明 |
| `src/lib.rs` | 模块聚合 + 公共常量再导出（无逻辑） |
| `src/cli.rs` | clap 顶层 `Args` + 三个子命令 + `run()` |
| `src/config.rs` | 强类型配置、`EnvSource`（注入式环境读取）、默认值 |
| `src/addrpolicy.rs` | `PublishPolicy` → `AddrFilter` 映射 |
| `src/keys.rs` | 密钥文件读写（原子创建） |
| `src/tunnel.rs` | TCP ↔ QUIC stream 双向桥接（两端共用） |
| `src/connmgr.rs` | client 侧常驻连接管理器（断线重连） |
| `src/pathinfo.rs` | 路径快照与路径变更订阅（直连/中继判定） |
| `src/nat.rs` | NAT 画像解析与判定 |
| `src/portmap.rs` | UPnP / NAT-PMP / PCP 可用性探测 |
| `src/fw.rs` | Windows 防火墙规则安装 / 卸载 / 检测 |
| `src/diag.rs` | 体检报告的数据结构与渲染 |
| `src/commands/mod.rs` | 子命令模块声明 |
| `src/commands/server.rs` | 被控端：建端点、accept、桥接 |
| `src/commands/client.rs` | 控制端：常驻连接、监听本地 TCP、桥接 |
| `src/commands/diag.rs` | 网络体检 |
| `src/bin/irt.rs` | 薄壳入口 |
| `tests/e2e.rs` | 进程内 relay + server + client 的端到端字节一致性测试 |

**删除**：`src/bin/server.rs`、`src/bin/client.rs`（逻辑迁入 `src/commands/*`）。

---

## Task 1: crate 骨架 + 配置层 + 发布策略

**Files**
- Modify: `Cargo.toml`
- Create: `src/lib.rs`、`src/cli.rs`、`src/config.rs`、`src/addrpolicy.rs`、`src/commands/{mod,server,client,diag}.rs`、`src/bin/irt.rs`
- Delete: `src/bin/server.rs`、`src/bin/client.rs`

**Interfaces**

```rust
// src/addrpolicy.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishPolicy { RelayOnly, IpOnly, All }

impl PublishPolicy {
    pub fn parse(s: &str) -> anyhow::Result<Self>;   // 接受 relay|ip|all，大小写不敏感
    pub fn as_str(self) -> &'static str;
    pub fn to_addr_filter(self) -> iroh::address_lookup::AddrFilter;
}

// src/config.rs
/// 注入式环境变量来源，避免测试污染进程环境。
#[derive(Debug, Clone, Default)]
pub struct EnvSource { vars: std::collections::BTreeMap<String, String> }
impl EnvSource {
    pub fn from_process() -> Self;
    pub fn from_pairs(pairs: &[(&str, &str)]) -> Self;
    pub fn get(&self, key: &str) -> Option<&str>;
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub key_file: std::path::PathBuf,
    pub rdp_target: std::net::SocketAddr,
    pub publish: PublishPolicy,
    pub relay_mode: iroh::RelayMode,
    pub allow_list: Vec<iroh::EndpointId>,
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub remote: iroh::EndpointId,
    pub listen: std::net::SocketAddr,
    pub relay_mode: iroh::RelayMode,
}

pub fn default_key_file() -> std::path::PathBuf;
pub fn default_rdp_target() -> std::net::SocketAddr;
pub fn default_listen() -> std::net::SocketAddr;
```

`src/cli.rs` 定义 clap 类型 `Args`（顶层）、`ServerArgs`、`ClientArgs`、`DiagArgs`，并把 `ServerArgs + &EnvSource` 解析成 `ServerConfig`、`ClientArgs + &EnvSource` 解析成 `ClientConfig`。**解析优先级：CLI > 环境变量 > 默认值。**

环境变量契约：

| 变量 | 作用 | 默认 |
|---|---|---|
| `IRT_PUBLISH` | `relay`\|`ip`\|`all` | `relay` |
| `IRT_KEY_FILE` | 密钥文件路径 | `default_key_file()` |
| `IRT_RDP` | 被控端 RDP 地址 | `127.0.0.1:3389` |
| `IRT_LISTEN` | 控制端监听地址 | `127.0.0.1:13389` |
| `IRT_RELAY` | 自建 relay URL（逗号分隔） | n0 公共 relay |
| `IRT_ALLOW` | 白名单 endpoint id（逗号分隔） | 不限制 |
| `NO_RELAY` | 存在则禁用 relay | 关闭 |
| `FORCE_RELAY` | 存在则发布 relay+IP | 关闭 |
| `FORCE_IPV6` | 存在则只发布 IPv6 | 关闭 |

**Steps**

1. [ ] 更新 `Cargo.toml`：`iroh = { version = "1.0", features = ["unstable-net-report"] }`；新增 `portmapper = "0.19"`、`serde = { version = "1", features = ["derive"] }`、`serde_json = "1"`；`tokio` features 补 `sync`、`time`；`clap` features 补 `env`；新增 `[dev-dependencies] iroh = { version = "1.0", features = ["test-utils"] }`
2. [ ] 写 `src/addrpolicy.rs`，含 `#[cfg(test)] mod tests`：`parse` 接受 `relay`/`ip`/`all`/`RELAY`；非法值返回错误且错误信息含该字符串；`to_addr_filter` 对 `RelayOnly` 过滤掉所有 IP 地址、对 `IpOnly` 过滤掉 relay 地址、对 `All` 全部保留（用 `iroh::endpoint_info::EndpointData` 或直接构造 `Vec<TransportAddr>` 断言过滤结果）
3. [ ] 运行 `cargo test addrpolicy` —— 应通过（此时 `Cargo.toml` 里 `iroh` feature 已就位）
4. [ ] 写 `src/config.rs`：`EnvSource`、`ServerConfig`、`ClientConfig`、三个 `default_*` 函数；含测试：`default_key_file()` 以 `server.key` 结尾且是绝对路径；`EnvSource::from_pairs` 的 `get` 行为
5. [ ] 写 `src/lib.rs`：只做 `pub mod` 声明 + 再导出 `ALPN`（`b"iroh-rdp-tunnel/0"`）、`RDP_LOCAL`、`LISTEN_ADDR`、`BUILD_TAG`（`"v0.2.0"`）
6. [ ] 写 `src/cli.rs`：`Args { #[command(subcommand)] command: Command }`、`Command::{Server,Client,Diag}`、三个子命令的 clap 结构、`pub async fn run() -> anyhow::Result<()>`；配置解析函数 `resolve_server(&ServerArgs, &EnvSource) -> anyhow::Result<ServerConfig>` 与 `resolve_client(...)`；含测试：CLI 覆盖环境变量、环境变量覆盖默认值、`IRT_PUBLISH=ip` 覆盖默认 `relay`
7. [ ] 写 `src/commands/{mod,server,client,diag}.rs` 骨架：`mod.rs` 声明三个子模块；每个子模块一个 `pub async fn run(...) -> anyhow::Result<()>`，暂时返回 `Ok(())` 并打印「未实现」
8. [ ] 写 `src/bin/irt.rs`：`fn main() -> anyhow::Result<()> { iroh_rdp_tunnel::cli::run().await }`
9. [ ] 删除 `src/bin/server.rs`、`src/bin/client.rs`
10. [ ] `cargo test` 全绿；`cargo build --release` 无警告；`cargo run --release --bin irt -- --help` 与 `... server --help` 正常输出
11. [ ] 提交：`重构为单一 irt 入口并抽出配置层`

---

## Task 2: `irt server` —— 持久化 id + relay-only 发布 + 桥接

**Files**
- Create: `src/keys.rs`、`src/tunnel.rs`
- Modify: `src/commands/server.rs`、`src/lib.rs`

**Interfaces**

```rust
// src/keys.rs
/// 读取密钥文件；不存在则原子创建（写临时文件 + rename）。文件内容为 32 字节原始私钥。
pub fn load_or_create_secret_key(path: &std::path::Path) -> anyhow::Result<iroh::SecretKey>;

/// 把 endpoint id 以小写十六进制写一份同名 `.txt`（best-effort，失败不报错）。
pub fn write_endpoint_id_hint(path: &std::path::Path, id: iroh::EndpointId) -> anyhow::Result<()>;

// src/tunnel.rs
/// server 侧：QUIC 双向流 ↔ 本地 TCP。
pub async fn bridge_quic_to_tcp(
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    tcp: tokio::net::TcpStream,
);

// src/commands/server.rs
/// 可被集成测试直接使用的服务端运行时。
pub struct ServerRuntime {
    pub endpoint: iroh::Endpoint,
    pub handler: BridgeHandler,
}
pub struct BridgeHandler {
    pub rdp_target: std::net::SocketAddr,
    pub allow_list: Vec<iroh::EndpointId>,
}
pub async fn build(cfg: &ServerConfig) -> anyhow::Result<ServerRuntime>;
pub async fn run(cfg: ServerConfig) -> anyhow::Result<()>;
```

**关键实现约束（对照 iroh 1.0.2 源码核对过）**

- **不要用 `presets::N0` 再追加第二个 `PkarrPublisher`。** `presets::N0` 内部已经注册了一个 `PkarrPublisher::n0_dns()`（默认 `relay_only` 过滤），追加第二个会让**同一个 endpoint id 在 pkarr 上出现两条竞态记录**，发布内容不确定。
  正确做法：用 `presets::Minimal`（只设置 crypto provider）自行组装：
  ```rust
  let endpoint = Endpoint::builder(presets::Minimal)
      .secret_key(secret_key)
      .relay_mode(cfg.relay_mode)
      .alpns(vec![ALPN.to_vec()])
      .portmapper_config(PortmapperConfig::default())
      .address_lookup(PkarrPublisher::n0_dns().addr_filter(cfg.publish.to_addr_filter()))
      .address_lookup(DnsAddressLookup::n0_dns())
      .bind()
      .await?;
  ```
  （`DnsAddressLookup::n0_dns()` 提供 DNS 解析侧；`PkarrPublisher::n0_dns()` 提供发布侧。两者都必须有，否则客户端解析不到或服务端发布不出去。）
- `endpoint.online().await` 之后再打印地址，确保 relay URL 已确定。
- `BridgeHandler::accept` 里先查 `allow_list`（非空则比对 `conn.remote_id()`，不匹配直接 `Err(AcceptError::from_err(...))`），再 `accept_bi()`，再 `TcpStream::connect(self.rdp_target)`，失败时错误信息里带上目标地址。

**Steps**

1. [ ] 写 `src/keys.rs` + 测试：临时目录里 `load_or_create_secret_key` 首次调用生成 32 字节文件；第二次调用返回**相同**的 `SecretKey`（`public()` 相等）；文件长度恰为 32
2. [ ] `cargo test keys` 应通过
3. [ ] 写 `src/tunnel.rs` + 测试：用 `tokio::io::duplex` 造两对内存流，断言 `bridge_quic_to_tcp` 之后字节双向透传且一侧 `finish()` 后另一侧能读到 EOF
4. [ ] `cargo test tunnel` 应通过
5. [ ] 写 `src/commands/server.rs`：`build()` 按上面的约束组装 Endpoint；`run()` 打印 banner（endpoint id、密钥文件路径、发布策略、home relay、公网端点、RDP 目标）后进入 accept 循环，直到 `ctrl_c()`
6. [ ] 手工验证：`cargo run --release --bin irt -- server` 打印出 endpoint id；**再跑一次，确认 id 与第一次完全相同**（这是 Task 2 的验收点）
7. [ ] `cargo test` 全绿
8. [ ] 提交：`server 持久化 endpoint id 并改用 relay-only 发布策略`

---

## Task 3: `irt client` —— 常驻连接 + 每 TCP 一条 stream

**Files**
- Create: `src/connmgr.rs`
- Modify: `src/commands/client.rs`、`src/tunnel.rs`

**Interfaces**

```rust
// src/connmgr.rs
/// 维护一条到远端的常驻 QUIC 连接，断线自动重连（指数退避，上限 5s）。
pub struct ConnManager {
    remote: iroh::EndpointId,
    endpoint: iroh::Endpoint,
    conn_rx: tokio::sync::watch::Receiver<Option<iroh::endpoint::Connection>>,
}
impl ConnManager {
    pub fn start(endpoint: iroh::Endpoint, remote: iroh::EndpointId) -> Self;
    /// 取当前可用连接；尚无连接则等待，最多 timeout。
    pub async fn connection(&self, timeout: std::time::Duration) -> anyhow::Result<iroh::endpoint::Connection>;
}

// src/tunnel.rs
/// client 侧：本地 TCP ↔ QUIC 双向流。
pub async fn bridge_tcp_to_quic(
    local: tokio::net::TcpStream,
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
);
```

**Steps**

1. [ ] 写 `src/tunnel.rs` 的 `bridge_tcp_to_quic` + 测试（与 Task 2 的 duplex 测试对称）
2. [ ] 写 `src/connmgr.rs` + 测试：用一个假的 `Connection` 不可构造 → 改为测试 `ConnManager` 的**重连退避节奏**（用 `tokio::time::pause()` + `advance()` 断言第一次重试在 ~200ms、第二次 ~400ms，上限 5s）
3. [ ] `cargo test connmgr` 应通过
4. [ ] 写 `src/commands/client.rs`：启动 `ConnManager` → 打印「正在与远端建立连接…」→ 监听 `cfg.listen` → 每个 TCP 连接取共享连接后 `open_bi()` 再 `bridge_tcp_to_quic`
5. [ ] 手工验证：`cargo run --release --bin irt -- client <server 的 id>` 打印出远端 id 与本地监听地址，并出现「连接已建立」
6. [ ] `cargo test` 全绿
7. [ ] 提交：`client 改为复用单条常驻 QUIC 连接`

---

## Task 4: 端到端集成测试

**Files**
- Create: `tests/e2e.rs`

**测试要点**

- 用 `iroh::test_utils::run_relay_server()` 起进程内 relay（`iroh` dev-dependency 已开 `test-utils` feature），测试**不依赖外网**
- 起一个本地 TCP 回显服务作为「假 RDP」，拿到它的 `SocketAddr` 当作 `ServerConfig::rdp_target`
- server 侧：`commands::server::build(&cfg)` → `Router::builder(rt.endpoint).accept(ALPN.to_vec(), rt.handler).spawn()`
- client 侧：另建一个 `Endpoint`（同样 `RelayMode::custom([relay_url])`），用 `EndpointAddr { id: server_id, addrs: {TransportAddr::Relay(relay_url)} }` 直连（**绕开 DNS**，测试只验证隧道本身）
- 断言：写入 64 KiB 随机字节 → 回显 → **逐字节相等**
- 断言：server 侧 `BridgeHandler` 的 `allow_list` 生效——用一个不在白名单的 endpoint id 连接会被拒绝
- 断言：连接建立后 `describe_path(&conn).is_some()`（Task 5 落地前先留空断言，Task 5 补上具体断言）

**Steps**

1. [ ] 写 `tests/e2e.rs` 第一个用例：`tunnel_roundtrip_preserves_bytes`
2. [ ] `cargo test --test e2e` —— 第一次可能因为 relay 与客户端 home relay 不一致而失败；此时在 client 侧显式 `RelayMode::custom([relay_url])` 指向同一个 relay
3. [ ] 测试通过后再加第二个用例：`allow_list_rejects_unknown_peer`
4. [ ] `cargo test` 全绿
5. [ ] 提交：`新增端到端集成测试`

---

## Task 5: 路径可观测 —— 直连 / 中继实时显示

**Files**
- Create: `src/pathinfo.rs`
- Modify: `src/commands/server.rs`、`src/commands/client.rs`、`src/lib.rs`

**Interfaces**

```rust
// src/pathinfo.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind { Direct, Relay }

#[derive(Debug, Clone)]
pub struct PathInfo {
    pub kind: PathKind,
    pub remote: String,                 // "171.37.192.67:34622" 或 relay url
    pub rtt: Option<std::time::Duration>,
}

/// 读取连接当前**被选中**的路径。
pub fn describe_path(conn: &iroh::endpoint::Connection) -> Option<PathInfo>;

/// 订阅路径变更；回调在路径被选中/切换时触发。
pub fn spawn_path_monitor(
    conn: iroh::endpoint::Connection,
    on_change: impl Fn(PathInfo) + Send + Sync + 'static,
) -> tokio::task::JoinHandle<()>;
```

**实现要点（对照 iroh 1.0.2 源码）**

- `conn.paths()` → `PathList`，用 `.iter()` 遍历找 `path.is_selected()` 为真的那一条
- `Path::is_ip()` / `Path::is_relay()` → 判定 `PathKind`
- `Path::remote_addr()` → `&TransportAddr`（`TransportAddr::Ip(SocketAddr)` / `TransportAddr::Relay(RelayUrl)` / `TransportAddr::Custom(_)`）
- `Path::rtt()` → `std::time::Duration`
- 变更订阅：`conn.path_events()` 返回 `PathEventStream`（是 `futures::Stream`），用 `futures::StreamExt::next` 驱动；`PathEvent` 是 `#[non_exhaustive]`，**必须带 `_ => {}` 兜底分支**
- `PathEvent::Selected { id, remote_addr, .. }` 触发回调

**输出格式（server 与 client 一致）**

```
 [路径] 中继 https://aps1-1.relay.n0.iroh.link./  RTT 41ms
 [路径] ✅ 已切换到直连  171.37.192.67:34622  RTT 37ms
```

**Steps**

1. [ ] 写 `src/pathinfo.rs` + 测试：`describe_path` 对一个假连接返回 `None`（无可选路径时）；`PathKind` 与 `TransportAddr` 的映射函数 `classify(&TransportAddr) -> PathKind` 覆盖 `Ip`/`Relay`/`Custom` 三种（`Custom` → `Relay`，因为不是直连 IP 路径）
2. [ ] `cargo test pathinfo` 应通过
3. [ ] 在 `commands/server.rs` 的 accept 回调与 `commands/client.rs` 的连接建立处接入 `describe_path` + `spawn_path_monitor`
4. [ ] 在 `tests/e2e.rs` 里补断言：连接建立后 `describe_path(&conn)` 返回 `Some`，且 `kind` 可判定
5. [ ] 手工验证：`cargo run --release --bin irt -- client <id>` 至少打印出一行「[路径] …」
6. [ ] `cargo test` 全绿
7. [ ] 提交：`新增直连/中继路径实时指示`

---

## Task 6: Windows 防火墙规则

**Files**
- Create: `src/fw.rs`
- Modify: `src/cli.rs`、`src/commands/server.rs`

**Interfaces**

```rust
// src/fw.rs
pub const RULE_NAME: &str = "iroh-rdp-tunnel (irt UDP inbound)";

/// 为指定可执行文件添加入站 UDP 放行规则（需要管理员）。
#[cfg(windows)]
pub fn install_udp_allow_rule(exe: &std::path::Path, rule_name: &str) -> anyhow::Result<()>;

/// 删除规则。
#[cfg(windows)]
pub fn remove_rule(rule_name: &str) -> anyhow::Result<()>;

/// 检测规则是否已存在且指向该 exe。
#[cfg(windows)]
pub fn has_allow_rule(exe: &std::path::Path, rule_name: &str) -> bool;

/// 非 Windows 平台：返回「不适用」错误，不 panic。
#[cfg(not(windows))]
pub fn install_udp_allow_rule(_: &std::path::Path, _: &str) -> anyhow::Result<()> { /* ... */ }
```

**实现要点**

- 用 `netsh advfirewall firewall add rule name="<rule_name>" dir=in action=allow program="<exe>" protocol=UDP enable=yes`
- 删除：`netsh advfirewall firewall delete rule name="<rule_name>"`
- 检测：`netsh advfirewall firewall show rule name="<rule_name>"`，输出里含 exe 路径即视为存在
- **非管理员运行时**：`netsh` 会返回权限错误，要把「需要管理员权限」翻译成一句人话提示，并给出可直接复制的完整命令
- 规则的 `program` 指向**当前 exe 的绝对路径**（`std::env::current_exe()`）

**CLI 契约**：`irt server --install-firewall-rule` / `irt server --uninstall-firewall-rule`。这两个 flag 走完就退出，不进入 accept 循环。

**Steps**

1. [ ] 写 `src/fw.rs` + 测试（非 Windows 上断言返回「不适用」错误；Windows 上跳过）
2. [ ] 在 `src/cli.rs` 的 `ServerArgs` 加两个 flag，在 `src/commands/server.rs` 里处理：装/卸规则后打印结果并返回
3. [ ] 在 server 启动 banner 里加防火墙自检行：
   ```
    防火墙        : ✅ 已放行入站 UDP
                 或
    防火墙        : ⚠ 未检测到入站 UDP 放行规则
                    → 请以管理员执行:  irt server --install-firewall-rule
   ```
4. [ ] `cargo test` 全绿
5. [ ] 提交：`内置 Windows 防火墙入站 UDP 放行规则`

---

## Task 7: `irt diag` 网络体检

**Files**
- Create: `src/nat.rs`、`src/portmap.rs`、`src/diag.rs`
- Modify: `src/commands/diag.rs`

**Interfaces**

```rust
// src/nat.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingBehavior { EndpointIndependent, Symmetric, Unknown }

#[derive(Debug, Clone)]
pub struct NatProfile {
    pub global_v4: Option<std::net::SocketAddrV4>,
    pub global_v6: Option<std::net::SocketAddrV6>,
    pub mapping: MappingBehavior,
    pub udp_v4: bool,
    pub udp_v6: bool,
    pub captive_portal: Option<bool>,
    pub preferred_relay: Option<iroh::RelayUrl>,
    pub relay_latencies: Vec<(iroh::RelayUrl, std::time::Duration)>,
    pub port_mapping: PortMappingStatus,
}

pub fn profile_from_report(report: &iroh::unstable_net_report::NetReport, pm: PortMappingStatus) -> NatProfile;

/// 「是否预期能 P2P 直连」的判定与理由（中文文案）。
pub fn verdict(profile: &NatProfile) -> Verdict;

pub struct Verdict { pub ok: bool, pub headline: String, pub reasons: Vec<String>, pub advice: Vec<String> }

// src/portmap.rs
#[derive(Debug, Clone)]
pub enum PortMappingStatus {
    Unsupported,
    Partial { upnp: bool, nat_pmp: bool, pcp: bool },
    Mapped { external: std::net::SocketAddrV4 },
    ProbeFailed(String),
    Unknown,
}
pub async fn probe() -> PortMappingStatus;

// src/diag.rs
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiagReport { pub profile: NatProfileView, pub verdict: VerdictView }
pub fn render(report: &DiagReport) -> String;      // 人类可读
pub fn render_json(report: &DiagReport) -> String;  // --json
```

**实现要点**

- NAT 画像来自 `Endpoint::net_report()`（需 `unstable-net-report` feature）：
  ```rust
  let mut watcher = endpoint.net_report();
  let report = tokio::time::timeout(Duration::from_secs(20), watcher.initialized()).await??;
  ```
  - `Report::mapping_varies_by_dest()` → `Option<bool>`：`Some(false)` = EIM（端点无关映射）；`Some(true)` = 对称 NAT；`None` = 未知
  - `Report::global_v4` / `global_v6` → 公网端点
  - `Report::relay_latency.iter()` → `(Probe, &RelayUrl, Duration)`
  - `Report::preferred_relay`
- **过滤行为测不了**：iroh 的 net_report 只测映射行为。`diag` 必须**明确标注「NAT 过滤行为：未测量（iroh 无法直接探测）」**，并说明「iroh 的打洞走双方同时发包，因此不依赖放行任意来源的入站」。**不得**伪造一个过滤行为结论。
- 端口映射探测用 `portmapper` crate：`Client::new(portmapper::Config::default()).probe()` → `oneshot::Receiver<Result<ProbeOutput, ProbeError>>`，`ProbeOutput { upnp, pcp, nat_pmp }`
- `--json` 输出用 `serde_json::to_string_pretty`

**输出格式**

```
=========================================================
 iroh-rdp-tunnel 网络体检
=========================================================
 公网 IPv4 端点   : 171.37.192.67:34622
 NAT 映射行为     : 端点无关映射 (EIM)  ✅ 公网端点稳定，可通告
 NAT 过滤行为     : 未测量（iroh 无法直接探测；严格验证见 netdiag/filter-proof.js）
 UDP 可用         : IPv4 ✅   IPv6 ❌（无全局地址）
 端口映射         : UPnP ❌  NAT-PMP ❌  PCP ❌（不支持）
                   → 不影响：EIM 映射下内端口固定即端点稳定，打洞不依赖端口映射
 最近中继         : aps1-1.relay.n0.iroh.link.  41ms

 判定: ✅ 具备 P2P 直连条件
   · 映射为 EIM ⇒ 通告的公网端点稳定，对端能对上号
   · iroh 的打洞走「双方同时发包」，不需要 NAT 放行任意来源入站
   · 你的「地址依赖过滤」不会阻断打洞
   · 无 UPnP 不影响（仅损失「首包更快」的机会）
 建议:
   1. server 保持默认 --publish relay
   2. 管理员执行 irt server --install-firewall-rule
   3. 连接后看 client 输出是否出现「✅ 已切换到直连」
=========================================================
```

**Steps**

1. [ ] 写 `src/nat.rs` + 测试：`profile_from_report` 对 `mapping_varies_by_dest_ipv4 = Some(false)` 判为 `EndpointIndependent`，`Some(true)` 判为 `Symmetric`，`None` 判为 `Unknown`；`verdict` 在 `Symmetric` 时 `ok == false`
2. [ ] `cargo test nat` 应通过
3. [ ] 写 `src/portmap.rs` + 测试：探测失败时返回 `PortMappingStatus::Unknown`（不 panic、不 `unwrap`）
4. [ ] 写 `src/diag.rs` + 测试：`render` 的输出包含「NAT 过滤行为」与「未测量」字样（**防止以后有人把它悄悄改成已测量**）；`render_json` 能被 `serde_json::from_str` 解析回来
5. [ ] 写 `src/commands/diag.rs`：建 Endpoint（`presets::Minimal` + `RelayMode::Default`）→ 采 net report → 跑 portmap 探测 → 组装 → 渲染/JSON
6. [ ] 手工验证：`cargo run --release --bin irt -- diag` 输出上述报告，且「公网 IPv4 端点」与 `netdiag/public-endpoint.txt` 一致（`171.37.192.67`）
7. [ ] `cargo test` 全绿
8. [ ] 提交：`新增 irt diag 网络体检子命令`

---

## Task 8: 文档重写

**Files**
- Modify: `README.md`
- Modify: `DESIGN.md`（同步实现结果：模块名、最终接口、实际输出样例）

**README 必须包含**

1. **一句话定位** + 与旧版的差异说明（`server.exe`/`client.exe` → `irt server`/`irt client`/`irt diag`）
2. **快速开始**：编译 → `irt server` → 复制 id → `irt client <id>` → `mstsc /v:127.0.0.1:13389`
3. **工作原理图**：relay 建连 → 双方同时打洞 → 自动迁移直连（画出这条时间线）
4. **网络机制说明**：为什么默认发布 relay URL；为什么直连优先于中继（primary/backup 层）
5. **本机实测网络画像表**（照抄 DESIGN.md §1，并注明是 2026-11-06 实测）
6. **`irt diag` 用法与输出样例**
7. **排障决策树**：连接不上 / 一直走中继 / 首帧慢，各给 2–3 条可执行动作
8. **CLI 参考表**（三个子命令的完整 flag 列表 + 环境变量表）
9. **旧环境变量兼容说明**（`NO_RELAY`/`FORCE_RELAY`/`FORCE_IPV6`）

**Steps**

1. [ ] 重写 `README.md`
2. [ ] 把实现后的实际输出粘贴进 README（用真实运行结果，不要手写编造）
3. [ ] 同步 `DESIGN.md`：把 `src/commands/*` 的最终接口签名、`Preset::Minimal` 而非 `N0` 的原因、真实输出样例写进去
4. [ ] `cargo test` 全绿；README 里每条命令都实际跑过一遍
5. [ ] 提交：`重写 README 并同步设计文档`

---

## 验收清单（Task 8 之后）

- [ ] `cargo test` 全绿（含 `tests/e2e.rs`）
- [ ] `cargo build --release` 无警告
- [ ] `irt server` 连续两次启动，endpoint id **完全相同**
- [ ] `irt client <id>` 在**手机 4G/5G** 上连接后，输出出现「✅ 已切换到直连」（这是本次改造的唯一硬指标）
- [ ] `irt diag` 报告与 `netdiag/` 下的既有实测结论一致（公网端点 `171.37.192.67`、EIM）
