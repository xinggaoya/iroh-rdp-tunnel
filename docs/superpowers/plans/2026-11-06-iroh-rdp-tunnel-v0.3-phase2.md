# iroh-rdp-tunnel v0.3 阶段 2：rustp2p-quic 传输层 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把传输层从 iroh 换成 rustp2p-quic，让对称 NAT 下的客户端也能 P2P 直连，同时保住现有的诊断、路径可观测、防火墙管理与单入口 CLI。

**Architecture:** 抽出 `Transport` trait 作为传输层边界，iroh 与 rustp2p-quic 各一个适配器。数据面复用现有 `src/tunnel.rs` 的泛型 bridge（quinn stream 与 iroh stream 同为 `AsyncRead`/`AsyncWrite`，adapter 很薄）。控制面复用现有 `src/connmgr.rs` 的常驻连接 + 自动重连模型。rustp2p-quic 的 poll 式路径状态由 adapter 转换成 v0.2 已有的 push 式事件模型，`src/pathinfo.rs` 原样复用。

**Tech Stack:** Rust 1.99 / edition 2021、tokio、rustp2p-quic 0.1.2（Apache-2.0）、quinn、clap、serde。

**Spec:** `docs/superpowers/specs/2026-11-06-iroh-rdp-tunnel-v0.3-design.md`（§5 方案 C、§7 详细设计、§9 决策分类）

## Global Constraints

- **单一 exe**：所有子命令仍在 `irt` 一个二进制里（决策 D8）
- **Windows 优先**：只保证 Windows；其他平台不承诺
- **中继永远兜底**：任何时候连接失败都必须能回落到中继（反目标 AG1）
- **不动这些既有资产**：`src/fw.rs`（防火墙）、`src/keys.rs`（密钥持久化）、`src/lookup.rs`（端点查询）、`src/config.rs`（配置层）、`src/tunnel.rs` 的泛型 bridge 核心
- **`--transport` 默认保持 `iroh`**：新后端是可选的，出问题立即退回
- **VPS 凭据不进版本库**：部署用密码只出现在本地临时脚本与本机环境变量中
- **不破坏 VPS 现有服务**：该机跑着 1Panel/openresty/gitea/数据库/hysteria2；只使用空闲端口（`443` 已被占用），不改动现有容器与配置
- **注释与文档用中文**（与现有代码一致）
- **每个任务结束提交一次**，提交信息用中文

## Review Focus

以下五类输入/失效模式，最容易在真机上咬人，而单测覆盖不到：

1. **对称 NAT 下打洞的时序** —— 打洞是后台周期性发包，「直连路径已打开」可能出现在连接建立后几十秒，路径可观测不能只看连接建立那一刻
2. **`--transport rustp2p` 下白名单语义** —— 用户已同意降级为「字符串比对」，但**代码里不能让人误以为它是认证**（§9.4）
3. **中继回落** —— 打洞失败或中继不可达时，必须仍然能连上并跑通 RDP
4. **STUN 服务器不可达** —— `stun.miwifi.com` 等公共 STUN 在某些网络下不通；`public_port_range` 缺失会让对称 NAT 的端口预测失效，打洞退化为纯随机扫描（慢 10 倍）
5. **VPS 侧 443/udp 已被 openresty 占用** —— 部署脚本不得假设 443 可用

---

### Task 1: 可行性 spike —— rustp2p-quic 能否跑通端到端

**这是整个计划的门禁。** rustp2p-quic 0.1.2 与 quinn/tokio 的兼容性、API 稳定性、
「每个节点平等」模型的实际行为都未经验证。**跑不通就不要继续 Task 2+。**

**Files:**
- 新建：`spike/`（临时目录，验证通过后删除，不进版本库）
- 新建：`docs/superpowers/spike/rustp2p-quic-spike.md`（结论存档）

- [ ] **Step 1: 确认 rustp2p-quic 版本与依赖树**

```bash
cd /tmp/rustp2p && git log --oneline -1 && cat rustp2p-quic/Cargo.toml | head -40
```

记录：`rustp2p-quic` 版本、依赖的 `quinn` 版本、是否要求更新的 Rust edition。
若 `quinn` 版本与本项目 `Cargo.lock` 冲突，记录冲突点。

- [ ] **Step 2: 本地编译 rustp2p-quic 的 node example**

```bash
cd /tmp/rustp2p && cargo build -p rustp2p-quic --example node 2>&1 | tail -20
```

预期：编译成功。**若失败**（如 Rust 版本不够、依赖冲突），记录错误并停止本任务。

- [ ] **Step 3: 在 VPS 上编译/部署 bootstrap node**

用 Docker（VPS 有 Docker 29.2，无 Rust 工具链）：

```bash
# 在 VPS 上
docker run --rm -v /opt/rustp2p:/work -w /work rust:1.99-bookworm \
  cargo build -p rustp2p-quic --example node --release
```

端口选择：**VPS 上 443/udp 已被 openresty 占用** → 用 `8889/tcp+udp`（空闲）。

- [ ] **Step 4: 三节点连通性验证（本机 = peer B）**

```bash
# 本机（NAT 后，EIM）
./target/debug/examples/node --id peer-b --seed peer-b-seed --bind 0.0.0.0:0 \
  --bootstrap 107.172.191.12:8889 --stun stun.miwifi.com:3478
```

预期：node 启动后打印自己的 `peer_id`，并能通过 bootstrap 见到 peer A。

- [ ] **Step 5: 验证「每个节点平等」模型的转发**

让 peer B 向 peer A 发起一次隧道传输（node example 自带交互式命令），
确认数据经 VPS 中继转发成功，且**中继不解密**。

- [ ] **Step 6: 验证 NAT 观测与打洞**

确认 node 打印出：
- 自己的公网 IP / 端口（NatObserve）
- 对端的公网 IP / 端口
- 打洞尝试（punch）的日志

- [ ] **Step 7: 结论存档**

写 `docs/superpowers/spike/rustp2p-quic-spike.md`，包含：版本、编译产物、
连接日志、发现的问题、对 Task 2+ 的影响。

**Commit:** `spike: 验证 rustp2p-quic 端到端可行`

---

### Task 2: 传输层抽象 `src/transport/`

**Files:**
- 新建：`src/transport/mod.rs`（trait 定义 + 共享类型）
- 新建：`src/transport/iroh.rs`（从现有 `endpoint.rs`/`connmgr.rs` 抽出）
- 修改：`src/lib.rs`（加 `pub mod transport;`）
- 测试：`src/transport/mod.rs` 内联单元测试

- [ ] **Step 1: 写失败的测试 —— trait 的核心类型可构造**

在 `src/transport/mod.rs` 写单元测试：构造 `PeerRef`、验证 `PathState` 的
`is_direct()` / `is_relay()` 判定、以及 `PathEvent` 的转换函数
`to_event(state)` 对四种状态映射到 v0.2 的事件语义。

- [ ] **Step 2: 运行测试确认失败**

```bash
cargo test transport:: 2>&1 | tail -20
```

- [ ] **Step 3: 定义 trait**

```rust
/// 对端标识。
pub enum PeerRef {
    /// iroh 的 endpoint id（公钥指纹）。
    Iroh(iroh::EndpointId),
    /// rustp2p-quic 的 peer id（任意字符串）。
    Rustp2p(String),
}

/// 路径状态 —— 两个后端都归一化到这里。
pub enum PathState {
    /// 正在连接中。
    Connecting,
    /// 走中继。
    Relay { relay: String, rtt: Option<Duration> },
    /// 已建立直连（公网端点）。
    Direct { remote: String, rtt: Option<Duration> },
    /// 失败。
    Failed { reason: String },
}

/// 路径状态变化事件 —— 与 `src/pathinfo.rs` 已有的语义对齐。
pub enum TransportEvent {
    PathOpened { remote: String },
    PathSelected { remote: String, rtt: Option<Duration> },
    PathClosed { remote: String },
}

/// 一个可读写的字节流。
pub trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> AsyncStream for T {}

/// 传输层连接。
#[async_trait]
pub trait TransportConn: Send + Sync {
    async fn open_stream(&self) -> anyhow::Result<Box<dyn AsyncStream>>;
    fn path_state(&self) -> PathState;
    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<TransportEvent>;
}

/// 传输层端点。
#[async_trait]
pub trait TransportEndpoint: Send + Sync {
    async fn connect(&self, peer: &PeerRef) -> anyhow::Result<Arc<dyn TransportConn>>;
    async fn accept(&self) -> anyhow::Result<Arc<dyn TransportConn>>;
    fn path_state(&self) -> PathState;
}
```

**注意**：`async_trait` 需要加依赖 `async-trait = "0.1"`（或改用
`trait_variant`/手写 boxed future）。选择 `async-trait` 最省事。

- [ ] **Step 4: 实现 iroh 适配器**

把 `src/endpoint.rs` 的 `bind`/`bind_resolver_only` 与 `src/connmgr.rs` 的
`connection_loop` 改造成实现这两个 trait。**行为必须完全不变** ——
`src/connmgr.rs` 现有的重连退避逻辑（`reconnect_delay`）与
`STABLE_CONN_DURATION` 原样搬过去。

- [ ] **Step 5: 运行测试确认通过，且既有测试不破**

```bash
cargo test 2>&1 | tail -20
```

预期：124 个既有测试 + 新增测试全绿。

**Commit:** `抽象传输层：Transport trait 与 iroh 适配器，既有行为不变`

---

### Task 3: rustp2p-quic 适配器

**Files:**
- 新建：`src/transport/rustp2p.rs`
- 修改：`src/transport/mod.rs`（加 `pub mod rustp2p;`）
- 修改：`Cargo.toml`（加 `rustp2p-quic = "0.1.2"`、`async-trait = "0.1"`）
- 测试：`src/transport/rustp2p.rs` 内联单元测试

- [ ] **Step 1: 写失败的测试 —— 状态归一化函数**

单元测试只测**纯函数**（不打网络）：把 rustp2p-quic 的 route/link 状态
映射到 `PathState`。抽成纯函数 `map_link_state(link: &LinkState) -> PathState`。

- [ ] **Step 2: 运行测试确认失败**

- [ ] **Step 3: 加依赖并确认能编译**

```bash
cargo add rustp2p-quic@0.1.2 async-trait@0.1
cargo build 2>&1 | tail -20
```

**若依赖冲突**（quinn 版本等）：记录并解决 —— 优先让 rustp2p-quic 胜出，
因为传输层可替换而诊断/可观测不能。

- [ ] **Step 4: 实现适配器**

要点：
- `PeerRef::Rustp2p(id)` → `rustp2p_quic::PeerId::new(id)`
- `Endpoint::builder()` 设 `identity`（seed 由 `src/keys.rs` 的密钥派生，
  保证 id 稳定）、`bootstrap`、`stun_servers`（**默认不能为空**，
  见 Review Focus 第 4 条）、`max_assistant_sockets`（默认 4）
- `open_stream` → quinn 的 `SendStream`/`RecvStream` 组合成
  `Box<dyn AsyncStream>`（用 `tokio::io::join` 或 `quinn::SendStream`+`RecvStream`
  的适配器）
- **路径状态是 poll 式的** → 起一个后台任务定期读状态，转换成
  `TransportEvent` 广播出去（这样 `src/pathinfo.rs` 不用改）

- [ ] **Step 5: 运行测试确认通过**

**Commit:** `新增 rustp2p-quic 传输层适配器`

---

### Task 4: CLI 与配置接入

**Files:**
- 修改：`src/cli.rs`（`--transport`、`--peer`、`--bootstrap`、`--node-id`）
- 修改：`src/config.rs`（`ClientConfig`/`ServerConfig` 加字段 + 优先级解析）
- 修改：`src/commands/client.rs`、`src/commands/server.rs`（按 transport 分派）
- 测试：`src/cli.rs` 内联单元测试（沿用现有 `EnvSource` 注入式测试风格）

- [ ] **Step 1: 写失败的测试 —— 参数解析与优先级**

测试用例：
- `--transport rustp2p` → `ClientConfig.transport == Rustp2p`
- `--transport rustp2p` + `IRT_TRANSPORT=iroh` → CLI 胜出
- `--bootstrap a --bootstrap b` → 列表保序
- `--peer <id>` 缺失且 transport=rustp2p → 报错信息清晰

- [ ] **Step 2: 运行测试确认失败**

- [ ] **Step 3: 实现参数与配置**

新增 CLI 参数（server 与 client 都要）：
```
--transport <iroh|rustp2p>     默认 iroh
--node-id <ID>                 rustp2p 的本机 peer id（默认从密钥派生）
--peer <ID>                    rustp2p 的对端 peer id（client 用）
--bootstrap <ADDR>             rustp2p 的 bootstrap 节点，可重复
--stun <ADDR>                  STUN 服务器，可重复（默认内置三个）
--assistant-sockets <N>        对称 NAT 打洞的辅助 socket 数，默认 4
```

环境变量对应：`IRT_TRANSPORT`、`IRT_NODE_ID`、`IRT_BOOTSTRAP`、`IRT_STUN`。

- [ ] **Step 4: 在 commands 里分派**

`src/commands/client.rs` 按 `cfg.transport` 选择
`transport::iroh::...` 或 `transport::rustp2p::...`。
**保持 `irt client <ENDPOINT_ID>` 的位置参数不变**（决策 M1），
`--peer` 作为 rustp2p 模式的补充。

- [ ] **Step 5: 运行测试确认通过**

**Commit:** `CLI 与配置接入 --transport/--peer/--bootstrap`

---

### Task 5: 路径可观测适配

**Files:**
- 修改：`src/pathinfo.rs`（接受 `TransportEvent` 而非 iroh `PathEvent`）
- 修改：`src/transport/iroh.rs`（把 iroh 的 `PathEvent` 转成 `TransportEvent`）
- 测试：`src/pathinfo.rs` 内联单元测试

- [ ] **Step 1: 写失败的测试**

现有 `pathinfo.rs` 的测试（`transition_labels_cover_all_cases`、
`is_public_endpoint_detection_filters_private_addresses` 等）必须继续通过 ——
**这意味着改造后 `PathKind`/`PathInfo` 的语义不变**，只是事件来源变了。
补一个测试：`TransportEvent::PathOpened` + 公网地址 → 打印「🔓 公网直连路径已打开」。

- [ ] **Step 2: 运行测试确认失败**

- [ ] **Step 3: 改造 pathinfo**

把 `spawn_path_monitor` / `spawn_path_reporter` 的事件源从
`conn.path_events()` 换成 `TransportConn::subscribe()`。
`PathInfo`/`PathKind`/`describe`/`transition_label` 的对外语义**不动**。

- [ ] **Step 4: 运行测试确认通过**

**Commit:** `路径可观测适配到 Transport 事件模型`

---

### Task 6: 诊断扩展 —— rustp2p 的 NAT 画像

**Files:**
- 修改：`src/diag.rs`（NAT 画像可来自 rustp2p 的 `nat_info`）
- 修改：`src/nat.rs`（画像结构扩展：端口范围、映射地址）
- 测试：`src/nat.rs` 内联单元测试

- [ ] **Step 1: 写失败的测试**

`NatProfile` 增加字段：
```rust
/// 对称 NAT 的端口分配范围（0 = 未知）。
pub port_range: u16,
/// 已知的公网 UDP 映射地址。
pub mapping_udp: Vec<String>,
```
测试：`mapping_varies_by_dest == true` 且有 `port_range` 时，
判定信息里要出现「端口范围」这一项（因为它决定穷举打洞的可行性）。

- [ ] **Step 2: 运行测试确认失败**

- [ ] **Step 3: 实现**

`irt diag --transport rustp2p` 时从 rustp2p 的 `nat_info` 取
`nat_type` / `public_ips` / `public_udp_ports` / `public_port_range`，
填进 `NatProfile`。iroh 后端保持现有 `profile_from_report` 路径。

- [ ] **Step 4: 运行测试确认通过**

**Commit:** `诊断支持 rustp2p 的 NAT 画像与端口范围`

---

### Task 7: VPS 部署

**Files:**
- 新建：`docs/deploy/rustp2p-node-vps.md`（部署手册）
- 新建：`deploy/rustp2p-node/docker-compose.yml`
- 新建：`deploy/rustp2p-node/config.toml`（若需要）

- [ ] **Step 1: 确定端口与目录**

- 端口：`8889/tcp+udp`（VPS 上空闲；**443 已被 openresty 占用**）
- 目录：`/opt/rustp2p`
- **不改动** VPS 上任何现有容器与 openresty 配置

- [ ] **Step 2: 写 docker-compose**

单容器：rust 镜像 + 挂载预编译二进制（或在镜像内 `cargo build`）。
节点参数：`--id <node-id> --seed <seed> --bind 0.0.0.0:8889`。
⚠️ **seed 必须持久化**（否则重启后 peer id/证书变了）；
用 named volume 或 bind mount 存 seed 文件。

- [ ] **Step 3: 在 VPS 上部署并验证**

```bash
docker compose up -d
docker compose logs --tail 50
```

验证：日志里有 peer id；`ss -ulnp | grep 8889` 有监听。

- [ ] **Step 4: 从本机验证连通**

```bash
./node --id peer-b --seed peer-b-seed --bind 0.0.0.0:0 --bootstrap 107.172.191.12:8889
```

- [ ] **Step 5: 写部署手册**

包含：前置条件、部署步骤、端口说明、**常见问题**（443 被占用、
STUN 不通、seed 丢失导致 id 变化）。

**Commit:** `新增 VPS 部署手册与 docker-compose`

---

### Task 8: 端到端验证

**Files:**
- 修改：`tests/e2e.rs`（新增 rustp2p 后端的 e2e）
- 新建：`docs/superpowers/spike/rustp2p-e2e-result.md`（验证结论存档）

- [ ] **Step 1: 加一个 rustp2p 后端的 e2e**

在现有 e2e 的基础上，用本机起的 rustp2p node 作为 bootstrap，
两端用 rustp2p 传输层跑通「本地 TCP → 隧道 → 远端 TCP」。

**注意**：CI/本地无对称 NAT，此 e2e 只能验证**中继路径**可用，
不能验证打洞成功。打洞验证见 Step 3。

- [ ] **Step 2: 运行全部测试**

```bash
cargo test 2>&1 | tail -20
cargo clippy --all-targets 2>&1 | grep -E "^warning|^error" | grep -v msvc_spectre
cargo build --release 2>&1 | tail -5
```

预期：无警告、无错误、全绿。

- [ ] **Step 3: 真机验证（需要用户的第二台机器）**

在**用户那台对称 NAT 的机器**上跑 client，观察：
- 是否出现「✅ 已切换到直连」
- `irt diag --transport rustp2p` 的 NAT 画像（端口范围、映射地址）

若未直连：按 §9.4 的缓解措施排查（`--allow` 白名单、punch_whitelist）。

- [ ] **Step 4: 存档结论**

**Commit:** `e2e：rustp2p 后端覆盖与验证结论存档`

---

## 回退策略

任一任务卡住时，`--transport iroh` 始终可用，功能完整（只是走中继、延迟高）。
**不要在 iroh 后端上做破坏性改动** —— 它是安全网。
