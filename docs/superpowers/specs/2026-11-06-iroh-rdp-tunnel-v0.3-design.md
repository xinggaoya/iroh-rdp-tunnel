# iroh-rdp-tunnel v0.3 设计：自建中继保可用 + rustp2p 传输层争取直连

日期：2026-11-06
状态：待批准
前置：v0.2 已合并到 `main`（`5fa0ab3`），功能可用但走中继且延迟偏高

---

## 1. 意图与「为什么」

用户要在**两台不同网络**的 Windows 机器之间做 RDP：家里（联通 10G-GPON 光猫，
`192.168.1.1` → `171.37.192.67`）与外面的控制端（公司网/热点，有全局 IPv6
`2408:845d:102:6406:...`）。

v0.2 已经解决「连不上」，但两件事没解决：

1. **延迟高**：默认走 n0 欧洲中继 `euc1-1`，路径 RTT **457ms**，RDP 卡到不可用。
2. **打不通直连**：客户端 NAT 是**映射随目标变化**（非 EIM），iroh 的打洞候选
   必然对不上号，实测跨网从未出现「公网直连路径已打开」。

用户的目标（明确表述）：**「两者都要：先保证可用，再争取直连」**，
并且**有云服务器 / VPS** 可用。

---

## 2. 已确认的事实（本项目的调试结论，不是推测）

| 事实 | 依据 |
|---|---|
| 客户端 NAT：映射随目标变化（非 EIM） | iroh `net_report/report.rs:95` → `mapping_varies_by_dest_ipv4 = Some(true)`；客户端日志两次 `IPv4 address detected by QAD varies by destination` |
| 服务端 NAT：EIM + 地址依赖过滤 | 用户的 netdiag 脚本实测 |
| 客户端**有**全局 IPv6，服务端**没有** | `Get-NetIPAddress` 显示服务端全部网卡只有 `fe80::`；客户端日志有 `2408:845d:102:6406:...` |
| iroh 1.0.2 的打洞候选**只能**来自 QAD | `socket.rs:1838` `DirectAddrType::Qad` ← `net_report.global_v4`（对**中继**观测到的端点） |
| QUIC `observed_address` 能纠正候选，但 iroh 未启用也未暴露 | `noq-proto/config/transport.rs` 的 `Role` 派生了 `Default` ⇒ `send=false, receive=false`；`iroh/endpoint/quic.rs` 只有 builder 方法 |
| 且纠正手段在 NAT 后无效 | 服务端自己的光猫会把源地址改写，服务端内部看不到对端真实 IP —— 只有**中继**能同时看到两端 |
| 端口映射（路由器固定转发 UDP 端口）可把映射变回 EIM | 映射与目标无关即 EIM |
| rustp2p/vnt 用「端口预测 + 范围穷举」破解对称 NAT | `rustp2p-core/src/punch/mod.rs` `punch_udp`：Phase 1 预测窗口（`port_range × 10`，≥100），Phase 2 全局随机扫描 1200~1500 端口（持久游标） |

**推导出的硬约束**：在 iroh 1.0.2 上，对称 NAT 下的直连**没有可行的修法**
（候选来源单一、observed address 未暴露、服务端在 NAT 后看不到对端真实 IP）。
要突破，只能**换掉传输层**，或**改变 NAT 行为**（端口映射 / 换网络 / IPv6）。

---

## 3. 目标 / 非目标 / 反目标

### 目标

- **G1** RDP 端到端延迟 **< 100ms**（现状 457ms）
- **G2** 对称 NAT 下也能 P2P 直连（不依赖 NAT 端口映射）
- **G3** 保留现有资产：单入口 `irt`、网络体检（`diag` / `--lookup`）、
  防火墙规则管理、路径可观测（直连/中继实时指示）
- **G4** 两端零配置：复制一行命令即可（沿用 v0.2 的可复制命令设计）

### 非目标

- **NG1** 不做虚拟网卡 / TUN 模式 —— 只需要「本地端口 → 远端端口」转发
- **NG2** 不替换 n0 公共基础设施 —— iroh 传输层仍保留为可选后端
- **NG3** 不追求打洞速度最优 —— 能通即可
- **NG4** 不做跨平台 —— 只支持 Windows（与现状一致）

### 反目标

- **AG1** 不为了「直连」而牺牲「一定能连上」——任何时候中继必须兜底
- **AG2** 不引入需要用户手工配置的对称 NAT 参数（端口映射由工具自动申请或明确报缺）

---

## 4. 约束

| | 约束 |
|---|---|
| C1 | 用户有 VPS。按「Linux 云主机，国内或香港」设计（**这是我的假设，待用户确认**；若实际是海外或 Windows Server，部署文档与延迟预期需相应调整） |
| C2 | 现有代码资产必须尽量保住：`src/tunnel.rs` 的泛型 bridge、`src/fw.rs` 防火墙管理、`src/diag.rs` 体检、`src/pathinfo.rs` 路径可观测、`src/lookup.rs` 端点查询 |
| C3 | rustp2p 的中继协议与 iroh-relay **不兼容**，两者不能混用；选 rustp2p 即意味着自建 `vnts` |
| C4 | 单 exe 分发（`irt`）是既有形态，v0.3 保持 |

---

## 5. 方案（Approaches）

### 方案 A：保留 iroh，自建就近中继

在 VPS 上跑 `iroh-relay`，两端 `--relay https://<vps> --ca-file <自签证书.pem>`。

- **优点**：改动最小（现有 `--relay`/`--ca-file` 已就位）；立即把延迟从 457ms 降到 30~50ms；不动传输层
- **缺点**：**放弃直连**（对称 NAT 下 iroh 无解）；依赖 iroh-relay 运维
- **适用**：直接满足 G1，不满足 G2

### 方案 B：直接改用 vnt

VPS 跑 `vnts`，两端跑 `vnt2_cli`，用它的端口映射把本地 `13389` 转到远端 `3389`。

- **优点**：工作量最小；**直连能力有**（vnt 的端口预测穷举）；生产验证过（3.3k star）
- **缺点**：**放弃本项目全部资产**（诊断、可观测、防火墙、CLI 形态）；只能跑 vnt 支持的转发模式
- **适用**：只要能用，不在乎我们的工具

### 方案 C：保留本项目资产，集成 rustp2p-quic 换传输层

把「传输 + 打洞 + 中继」换成 **`rustp2p-quic`**；VPS 上跑一个 rustp2p-quic node
充当 bootstrap / relay / NAT 观测者；本项目的诊断/可观测/防火墙/CLI 全部保留。

- **优点**：**同时满足 G1 与 G2**；保住 C2 的资产
- **缺点**：工作量最大；引入 rustp2p 依赖（需锁版本并评估 API 稳定性）
- **可行性已验证**（基于 rustp2p-quic 的实际 API）：
  - **有真 QUIC streams**（quinn）⇒ `src/tunnel.rs` 的泛型 bridge
    **直接复用**，不需要流重组适配器
  - **端到端 TLS**：rustp2p-quic README 明说
    “Every node is equal. A reachable node can relay traffic for other peers,
    but it **does not terminate their QUIC streams**.”
    ⇒ 中继只转发密文，**不需要专门的 relay 服务端**，`vnts` 完全用不上
  - `Builder::certificate_verifier(Arc<dyn CertificateVerifier>)`
    ⇒ 可以实现**证书固定**，保住 v0.2 的安全姿态（见 §9）
  - `Builder::nat_observers` / `max_assistant_sockets` / `stun_servers` /
    `mapping_udp_addrs` / `bootstrap` 覆盖 NAT 观测与打洞所需全部配置
  - 许可：rustp2p 为 Apache-2.0，本项目 MIT OR Apache-2.0，兼容；Windows 有支持

**⚠️ 关于「端口映射可由工具自动申请」——这条是错的，已从本文档删除。**
`Config::mapping_udp_addr` 是「**报告**已有映射」的字段，不是申请接口；
且家宽光猫三种协议（UPnP / NAT-PMP / PCP）全不支持。
诚实的做法是**明确报缺**并给出人工指引（见 §9「我的决定」第 2 条）。

### 选择：**A + C 组合**

用户目标「先保证可用，再争取直连」正好对应两个可独立交付的阶段：

- **阶段 1（A）**：VPS 上自建 iroh-relay → 立刻把延迟降到 30~50ms，G1 达成。
  交付物是部署文档 + 自签证书信任链，**不改 Rust 代码**。
- **阶段 2（C）**：集成 rustp2p 换传输层 → 争取 G2。阶段 1 的成果（VPS、
  证书、域名）在阶段 2 继续可用，只是换成 `vnts`。

阶段之间有**回退**：阶段 2 完成后，iroh 传输层仍保留为可选后端
（`--transport iroh|rustp2p`），任何时候可退回。

**为什么不选 B**：用户明确要「保留能力、争取直连」，B 等于放弃项目。

---

## 6. 阶段 1 详细设计：自建 iroh-relay

### 6.1 交付物

| | 内容 |
|---|---|
| `docs/deploy/relay-vps.md` | VPS 部署手册：安装 `iroh-relay`、生成自签证书、systemd unit、防火墙放行、验证 |
| `docs/deploy/relay-checklist.md` | 验收清单（可复制粘贴的命令 + 期望输出） |
| 工具侧 | **无需改动** —— `--relay` / `--ca-file` 已在 v0.2 就位 |

### 6.2 关键点

- **端口**（`iroh-relay-1.0.2/src/defaults.rs`）：
  `QUIC 7842/udp`、`HTTPS 443/tcp`、`HTTP 80/tcp`、`metrics 9090/tcp`。
  放行 `443/tcp` + `7842/udp`。（⚠️ QUIC 口是 **7842** 不是 7843。）
- **⚠️ 必须显式开启 `enable_quic_addr_discovery = true`**
  （`iroh-relay/src/main.rs:375` 的 `cfg_defaults::enable_quic_addr_discovery()`
  **默认返回 `false`**）。
  这不是可选项 —— 客户端的公网候选（`global_v4`）来自对中继的 QAD 探测，
  而 QAD 正是靠这个 QUIC 端口做的。不开它：
  ① 客户端学不到任何公网候选 ⇒ **自建中继下永远不可能直连**；
  ② QAD 驱动的中继选择也被静默禁用。
  （n0 的公共中继是开着的，所以用公共中继时看不出问题。）
- **证书**：自签。iroh-relay 用配置文件里的 `tls` 段加载证书链与私钥；
  两端用 `irt server --ca-file <CA.pem>` 信任。
  （v0.2 已把中继 TLS 信任改成「传入 CA 配置」而非「跳过校验」——见决策 D11。）
- **域名**：若 VPS 有域名，用域名而非 IP 做证书 SAN，避免换 IP 就要重签。
  ⚠️ `--ca-file` 只是**追加**信任根，**不会**关闭主机名校验 ——
  IP 与证书 SAN 不匹配会直接 TLS 握手失败。
- **降级预案**：自建中继挂了要能退回 n0 公共中继。
  ⚠️ 注意：`RelayMode::custom([...])` 构造的是 `RelayMap`，iroh 会按 QAD 延迟选
  home relay 并在变化时重新发布；而**可拨号的 relay URL 来自对端公布的内容**。
  所以**两端必须都配上两个 URL**，且切换不是瞬时的（要等 net report 刷新 + 重发布）。
  （见 §9「我的决定」第 3 条。）

### 6.3 验收

1. 两端 banner 的 `中继域名` 相同且等于自建 relay 的域名
2. `[路径·server]` 的 RTT **< 100ms**
3. RDP 实际可用（mstsc 拖窗口流畅）

---

## 7. 阶段 2 详细设计：集成 rustp2p

### 7.1 模块结构（沿用现有分层）

```
src/
├── transport/            ← 新增：传输层抽象，两种实现
│   ├── mod.rs            Transport trait（连接、双向流、路径状态、打洞状态）
│   ├── iroh.rs           现有 iroh 实现（从 endpoint.rs/connmgr.rs 抽出）
│   └── r2p.rs            rustp2p-quic 实现
├── tunnel.rs             不变（泛型 bridge）；quinn stream 与 iroh stream 都是
│                         AsyncRead/AsyncWrite ⇒ adapter 很薄
├── punch.rs              新增：打洞状态模型（供路径可观测与诊断使用）
├── diag.rs               扩展：NAT 画像改用 rustp2p 的 nat_info（更细：端口范围/映射地址）
├── pathinfo.rs           扩展：直连/中继判定改用 Transport 的路径状态
└── fw.rs / lookup.rs / keys.rs / config.rs / cli.rs   不变
```

### 7.2 关键设计决定

- **传输层用 trait 抽象**，不是 if/else 分支。理由：现有 `src/tunnel.rs` 已经是
  泛型 core + adapter 的结构，顺着做能保住 bridge 与其测试。
- **`Transport` trait 需要的能力**（由两个实现共同满足）：
  ```rust
  trait Transport {
      async fn connect(&self, peer: &PeerRef) -> Result<TransportConn>;
      async fn accept(&self) -> Result<TransportConn>;
      fn path_state(&self) -> PathState;      // 直连/中继/打洞进度
      fn nat_info(&self) -> Option<NatInfo>;   // 供 diag
  }
  trait TransportConn {
      async fn open_stream(&self) -> Result<TransportStream>;  // 双向流
  }
  ```
- **打洞协调协议**：参考 vnt-core 的协议头（peer 列表 / NAT 信息 / 打洞信号），
  在 `src/transport/rustp2p.rs` 内实现。**不复用 vnt-core 的代码**（避免耦合
  它的虚拟网卡与路由逻辑），只借鉴协议语义。
- **中继**：**不需要专门的 relay 服务端**。rustp2p-quic 的模型是「每个节点平等」，
  任何可达的节点都能为其他 peer 转发。VPS 上跑一个 rustp2p-quic node 即可，
  它的角色是 bootstrap（入口）+ relay（转发）+ NAT 观测者。
  （`vnts` 是 vnt-core 的 protobuf/WebSocket 协议服务端，**与 rustp2p 不兼容**，不用。）
- **身份与加密**：rustp2p-quic 的 `PeerId` 是**任意字符串**，证书来自 seed 且
  默认 `SkipCertificateVerification`。我们要**保留 v0.2 的安全姿态**：
  ① `PeerId` 用我们现有的 endpoint id（ed25519 公钥指纹）；
  ② 自签证书 + `Builder::certificate_verifier` 做**公钥固定**；
  ③ `--allow` 白名单在 accept 路径上强制。
  （见 §9「待用户确认」Q2 —— 若用户接受降级，工作量会小很多，但那是安全回退。）
- **回退**：保留 iroh 后端，`--transport` 切换；阶段 2 出问题可立即退回。

### 7.3 路径可观测的适配

v0.2 已经把「直连/中继」做成了明确信号（`🔓 公网直连路径已打开` /
`✅ 已切换到直连`）。rustp2p-quic 后端要给出等价信号。

⚠️ **不能用 `Puncher::punch_stats`** —— 它是**私有字段**
（`rustp2p-core/src/punch/mod.rs:64`），没有公开 API。
可用的信号是 **route / link 状态**（poll 式，与 iroh 的 push 式事件不同）：

| iroh（push） | rustp2p-quic（poll） |
|---|---|
| `PathEvent::Opened`（公网直连） | route 的 hop metric = 0 / link 为直接路径 |
| `PathEvent::Selected` | 隧道建立后首个数据流走通 |
| `relay_mismatch` 检查 | 中继地址比对（保留） |

**因此 `Transport` trait 必须同时支持两种形状**，或由 adapter 把 poll 状态
转成事件。实现时用后者（`pathinfo.rs` 只认事件，adapter 负责转换），
这样 v0.2 已有的路径可观测代码与测试可以原样复用。

### 7.4 验收

1. 跨网出现「✅ 已切换到直连」（**这是 G2 的唯一判据**）
2. 对称 NAT 的客户端上，端口预测/穷举能在可接受时间内命中
3. 打洞失败时**自动回落中继**，RDP 仍可用（AG1）
4. 现有 133 单测 + 4 e2e 全绿，且新增 rustp2p 后端的 e2e

---

## 8. 风险

| 风险 | 缓解 |
|---|---|
| rustp2p-core API 不稳定 / 与目标 Rust 版本不兼容 | 阶段 2 起步先做**可行性验证**：一个最小 client/server 能通过自建 `vnts` 完成 peer 发现 + 打洞 + 字节流，跑通才继续 |
| `vnts` 与 `rustp2p-core` 版本不匹配 | 锁定版本组合，写进文档；优先用 rustp2p 仓库的 docker-compose |
| 对称 NAT 穷举打洞耗时不可接受 | 打洞是**后台**进行，中继路径同时可用（AG1）；超时即回落 |
| 阶段 1 的 VPS 位置不佳，延迟仍高 | 阶段 1 可换机房；阶段 2 的直连不依赖 VPS 位置 |
| 替换传输层引入回归 | 双后端并存 + `--transport` 切换；e2e 覆盖两条路径 |

---

## 9. 决策分类（按 builder check 的三类）

### 9.1 已由对话/项目回答（已写入上文）

| | 问题 | 答案 |
|---|---|---|
| A1 | 走哪条传输层路线？ | **A + C 组合**：阶段 1 自建 iroh-relay 保可用，阶段 2 集成 rustp2p-quic 争取直连 |
| A2 | 用不用 `vnts`？ | **不用** —— rustp2p-quic「每个节点平等」模型不需要专门 relay 服务端，且 `vnts` 协议不兼容 |
| A3 | 阶段 2 用 rustp2p-core 还是 rustp2p-quic？ | **rustp2p-quic** —— 有真 QUIC streams（bridge 直接复用）、端到端 TLS、可注入证书校验器 |
| A4 | 打洞的具体机制？ | 端口预测（`port_range × 10`，≥100）+ 全局随机扫描（1200~1500/轮，持久游标）+ assistant sockets |
| A5 | iroh 后端是否长期保留？ | **保留**，加 `--transport` 切换；长期标记 deprecated 但不删 |

### 9.2 我的决定（合理实现者也能自己定，已定并写入上文）

| | 决定 | 理由 |
|---|---|---|
| M1 | **CLI 契约保持 `irt client <peer-id>` 形状**，不引入 vnt 的「组网码 + 设备名」 | 保住 v0.2 的一行命令体验（D18）与 `--allow` 白名单语义；rustp2p-quic 的 `PeerId` 本就是任意字符串，直接填 endpoint id |
| M2 | **端口映射：明确报缺 + 人工指引**，不做「自动申请」 | `mapping_udp_addr` 是报告字段不是申请接口；光猫三种协议全不支持；假装能申请是误导 |
| M3 | **n0 回落：文档化的手动切换 + 可见告警**，不做自动故障转移 | `RelayMode::custom` 的 home relay 由 QAD 延迟选出且切换滞后；自动故障转移要额外的健康检查与切换机制，与「阶段 1 不改 Rust 代码」矛盾。阶段 1 的产物是部署手册，不是新功能 |
| M4 | **STUN 服务器地址写入配置默认值**（`stun.miwifi.com:3478` 等） | rustp2p 的 `Config::default()` 的 `stun_servers` 是**空的**，而对称 NAT 的端口预测需要端口范围作为输入 |
| M5 | 阶段 2 起步先做**可行性验证 spike**（最小 client/server 通过自建 node 完成发现+打洞+字节流），跑通才继续 | 风险最高的一环（协议栈版本匹配、API 稳定性）在投入前先验证 |

### 9.3 只有你能回答（会改变要做什么）

| | 问题 | 为什么答案会改变计划 |
|---|---|---|
| **Q1** | **VPS 的具体事实**：(a) 有公网 IPv4 且**无 NAT**、**UDP 可达**吗？(b) 有域名吗（证书 SAN 要匹配）？(c) 能跑 Docker 或 Rust ≥ 1.91 工具链吗？(d) 位置（国内/香港/海外）？ | 阶段 1 的全部交付物就是一份部署手册，没有 (a)(b)(c) 写不出来；(a) 不满足则 iroh-relay 的 QUIC 口打不开，阶段 1 根本跑不起来。位置决定 G1 的延迟目标值是否现实 |
| **Q2** | **安全姿态**：阶段 2 是否必须保持 v0.2 的「公钥指纹身份 + 认证加密 + `--allow` 白名单」？还是接受 rustp2p-quic 的默认（`PeerId` 为任意字符串、默认跳过证书校验）？ | 这是**安全回退**，不能默默降级。保持则需实现证书固定 + 改造 `src/keys.rs`；不保持则 `irt` 会变成「任何能连上 VPS 的人都能接你的 RDP」 |
| **Q3** | **打洞的时间预算**：可接受的直连耗时是多少（30s / 5min / 不限）？以及——**「最终仍走中继」是否算 v0.3 的可接受结果**？ | 决定是否需要打洞进度状态机与超时提示，以及 §7.4 的验收标准。注意：G2 **无法在 CI 里回归测试**（没有对称 NAT），验收只能在你那两台真机上做，所以时间预算就是验收标准本身。穷举扫完 65535 个端口约需 44 轮（≈分钟级） |

---

## 10. 不在本次范围内

- 虚拟网卡 / TUN 模式
- 跨平台（Linux/macOS/Android 客户端）
- 多用户 / 权限模型
- 自动化的 VPS 部署（IaC）
