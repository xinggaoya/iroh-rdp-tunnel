# iroh-rdp-tunnel v0.2 设计文档

> 目标：让本项目在**实测网络画像**下真正做到 P2P 直连优先，并把「直连还是中继」变成**肉眼可见**的运行时指标。

---

## 1. 背景：本机网络画像（实测，非推测）

| 项目 | 实测结果 | 对实现的影响 |
|---|---|---|
| 公网 IP | `171.37.192.67`（联通 10G-GPON 光猫 `192.168.1.1`） | 可作为通告端点 |
| NAT **映射**行为 | **EIM 端点无关映射**（跨 3 个 STUN 一致） | 公网端点稳定 → 可通告、可打洞 |
| NAT **过滤**行为 | **地址依赖**：未通信来源的入站 UDP 全丢 | **必须双方同时发包** |
| CGNAT | 无 | 打洞成立的前提条件已满足 |
| UPnP / NAT-PMP / PCP | **三者全不支持** | 端口映射不可依赖，但 EIM 下不需要 |
| IPv6 | 无全局地址（仅 `fe80::`） | 只走 IPv4 |
| 延迟 | 国内 37ms / 0 丢包 | 直连体验远好于中继 |
| Windows 防火墙 | node.exe 等**无入站放行规则** | 远控程序必须自行放行 |
| RDP | 已开启，监听 3389 | 可直接用 |

**核心结论**：网络本身**支持 P2P**，但**不是「任意入站」模式**，必须走「**双方同时发包**」的打洞。

---

## 2. 机制澄清：iroh 的打洞是怎么工作的

对照 `iroh 1.0.2` 源码逐条核对：

| 事实 | 源码位置 | 含义 |
|---|---|---|
| 打洞基于 QUIC NAT Traversal 扩展 | `endpoint/quic.rs:528`（`max_remote_nat_traversal_addresses`） | 候选地址在**已建立的 QUIC 连接**上交换 |
| 打洞触发点 = 连接建立之后 | `socket/remote_map/remote_state.rs:917` `do_holepunching()` | **先建连，才能打洞** |
| 打洞 = 双方同时发包 | `conn.initiate_nat_traversal_round()` → 双方各自向对方候选地址发包 | 与实测结论完全一致 |
| relay 路径必须来自**对端公布的 RelayUrl** | `remote_state.rs:1514` `TransportAddr::Relay(url) => Addr::from((url, endpoint_id))` | **不公布 relay URL ⇒ 客户端建不出 relay 路径** |
| 直连优先于中继 | `socket/biased_rtt_path_selector.rs:94`：IPv4/IPv6 = primary 层，Relay = backup 层，跨层立即切换 | 公布 relay URL **不会**导致「一直走中继」 |

### 2.1 当前代码的一个致命缺陷

`server.rs` 现在默认 `AddrFilter::ip_only()` —— 它把 relay URL 从 pkarr 记录里剔掉了。后果链条：

```
ip_only() 剔除 relay URL
  → 客户端 DNS 解析不到对端 RelayUrl
  → iroh 建不出 relay 路径（remote_state.rs:1514）
  → 客户端只能直连 171.37.192.67:34622
  → 被光猫「地址依赖过滤」丢弃（未通信来源的入站 UDP 全丢）
  → 连接直接失败；且没有通道交换打洞候选，打洞也无从谈起
```

上个 commit 写的「iroh 会用自己的 relay 兜底」**不成立**。这也解释了此前观察到的 360ms 中继延迟：那是 `unfiltered()`（relay URL 有公布）时的回落行为。

### 2.2 正确模型

```
server 公布 relay URL（iroh 标准：AddrFilter::relay_only）
  → 客户端经 relay 建连（必定成功）
  → 已建立的连接上交换 NAT 候选地址
  → 双方同时发包 → 打洞成功 → iroh 立即切到直连路径（primary 层）
  → 之后全程直连，中继只做兜底
```

**这正是「双方同时发包」打洞模式，iroh 原生就实现了，不需要自己造。**

---

## 3. 设计决策

| # | 决策 | 理由 | 备选与否决理由 |
|---|---|---|---|
| D1 | **默认发布策略改为 `relay-only`** | §2.2；地址依赖过滤下唯一能保证建连的方式 | `ip-only` 已证实建不上；`all` 会让客户端先试直连、首包多等一个超时 |
| D2 | **新增「直连/中继 + RTT」实时指示** | 用户唯一需要的验收信号就是「看客户端显示直连还是中继」 | 只在文档里写没用，必须运行时可观测 |
| D3 | **endpoint id 持久化** | 现在 `SecretKey::generate()` 每次启动都变 id，复制粘贴成本高、无法写进脚本 | 固定 id 后可直接配防火墙/端口转发/收藏 |
| D4 | **内置 `diag` 网络体检** | 把 `netdiag/*.js` 的结论固化成工具，换网络环境时能自证 | 依赖外部 node 脚本不可持续 |
| D5 | **Windows 防火墙规则内置** | 实测 node.exe 都无入站放行；不放行必退化成中继甚至连不上 | 只在 README 写「记得放行」不够可靠 |
| D6 | **client 复用单条 QUIC 连接** | 现在每个 mstsc TCP 连接都新建一条 QUIC 连接 → 每次重打洞；改为常驻连接后打洞只发生一次 | 保持每连接新建会反复触发打洞，首帧延迟高 |
| D7 | **保留 `NO_RELAY` / `FORCE_RELAY` / `FORCE_IPV6` 旧环境变量** | 不破坏用户现有习惯 | 旧的 `FORCE_IPV4_ONLY` 从未真正生效过，一并清理 |
| D8 | **单一 `irt` 入口，三个子命令** | 只有一个 exe 要分发；子命令让「server / client / diag」在同一套配置层上；`bin/` 退化为薄壳，业务逻辑全部可单测 | 原设计的三个独立二进制（server/client/diag）—— 评审决定合并 |
| D9 | **用 `presets::Minimal` 自行组装 Endpoint，不用 `presets::N0` + 追加 publisher** | `presets::N0` 内部已注册 `PkarrPublisher::n0_dns()`（默认 `relay_only`），再追加第二个会让**同一 endpoint id 在 pkarr 上出现两条竞态记录**，发布内容不确定 | 沿用现有 `server.rs` 的 `presets::N0` + 第二个 publisher 写法 —— 实施计划阶段核对源码发现的问题 |
| D10 | **新增 `Discovery` 开关（Public / Disabled）** | 集成测试要能**关掉公共 pkarr / DNS**，否则测试依赖外网、还会把临时 endpoint id 往公共 pkarr 上写；自建 relay 场景同样需要 | 沿用 `presets::N0` 无法关掉发现服务 —— 实施阶段发现的问题 |
| D11 | **中继 TLS 信任用「传入 CA 配置」而不是「跳过校验」** | `CaTlsConfig::insecure_skip_verify()` 受 iroh-relay 的 `test-utils` feature 门控，**生产构建里根本不存在**；而且「跳过校验」本身是安全陷脚 | 一开始想加 `--insecure-relay` 开关，release 编译失败后改为 `--ca-file <PEM>` —— 正确的做法 |
| D12 | **路径事件流在 spawn 之前订阅** | 事件流是广播通道，晚订阅会丢掉「中继 → 直连」的迁移事件 —— 而那正是用户最想看到的一行 | 先在任务内部订阅，实测漏掉了迁移 —— 实施阶段发现的问题 |
| D13 | **endpoint id 解析前统一转小写** | iroh 的十六进制解码器只认小写（HEXLOWER），但用户复制来的 id 很可能带大写字母 —— Review Focus 明确点名了这一项 | 直接交给 iroh 解析，大写 id 会报「不是合法的 endpoint id」 |
| D14 | **防火墙检测按**路径**匹配，不解析 netsh 的标签名** | netsh 输出是**本地化**的（中文 Windows 上是「程序:」），而且非 verbose 模式根本没有程序路径行；路径本身不本地化 | 解析标签名（初版做法）→ 在中文 Windows 上 100% 误报 |
| D15 | **防火墙检测查**全部**规则，而不是只查我们自己的规则名** | Windows 会为监听端口的程序自动创建一条以 exe 文件名命名的入站 UDP 放行规则 —— 那条同样有效 | 只查 `RULE_NAME` → 明明已经放行了却一直提示「未检测到」 |
| D16 | **两端都在建连前先等 net report 就绪** | 打洞时**客户端**用 `REACH_OUT` 通告自己的可达地址（`noq/connection.rs:857`），而公网候选 `global_v4` 来自 net report 的 QAD 探测 —— net report 未就绪时通告出去的候选只有私网地址，服务端**连尝试都不会发起** | 连接建立即开始打洞 → 实测跨网始终不出现「直连路径已打开」，服务端一个公网包都不发 |
| D17 | **client banner 也要显示防火墙状态** | 打洞要**双向**：服务端往控制端公网映射端口发的包要穿过**控制端**的 Windows 防火墙。只给被控端装规则是常见疏漏 | client banner 不显示防火墙状态 → 两边看起来都正常，直连就是不成 |
| D18 | **中继一致性检测 + 打印可复制的客户端命令** | 两端各自自动选 relay 极易选到不同家，流量多一跳中继转发，RTT 从 ~400ms 涨到 1200ms | 只靠文字提醒用户「两端要加同一个 `--relay`」→ 实测连续三次被忽略；改为 server 直接打印带 relay 的完整命令 |
| D19 | **路径事件只报公网端点** | 本机多张虚拟网卡（192.168.0/52/104、172.29.x）会让路径事件刷屏，把真正的公网端点淹没 | 打印所有直连路径事件 → 一屏噪音，关键信息看不见 |
| D20 | **中继不一致告警改为周期检查** | 路径事件发生的瞬间本端往往还没连上 relay（home relay 为空），判不出来 → 告警被静默漏掉 | 只在事件驱动时判定 → 告警从不出现，用户以为没问题 |

---

## 4. 架构：模块划分

```
src/
├── lib.rs           crate 根：pub mod 声明、公共类型再导出
├── cli.rs           clap 定义：顶层 Args + 三个子命令 + run() 入口
├── config.rs        配置层：CLI + 环境变量 → 强类型配置（EnvSource 注入式）
├── keys.rs          密钥持久化：load_or_create_secret_key()
├── addrpolicy.rs    发布策略：PublishPolicy → AddrFilter 映射
├── endpoint.rs      iroh 端点组装（server/client 共用）+ CA 文件加载
├── nat.rs           NAT 画像：net_report 解析 → NatProfile + 判定
├── netaddr.rs       公网地址判定（RFC 6890，替代尚未稳定的 is_global()）
├── portmap.rs       端口映射探测：UPnP / NAT-PMP / PCP 可用性
├── pathinfo.rs      路径可观测：PathKind / describe_path / spawn_path_monitor
├── lookup.rs        查对端在 n0 上公布的地址（diag --lookup）
├── tunnel.rs        隧道核心：TCP ↔ QUIC stream 双向桥接（两端共用）
├── connmgr.rs       client 侧常驻连接管理器（自动重连）
├── fw.rs            Windows 防火墙规则安装/卸载/检测
├── diag.rs          网络体检报告组装与渲染（文本 + JSON）
├── commands/        子命令实现（纯逻辑，可被单测直接调用）
│   ├── mod.rs
│   ├── server.rs    被控端
│   ├── client.rs    控制端
│   └── diag.rs      网络体检
└── bin/
    └── irt.rs       薄壳：main() → iroh_rdp_tunnel::cli::run()
```

### 4.1 依赖方向

```
bin/irt.rs  ──►  cli ──► commands/{server,client,diag}
                                │
                                ├──► config ──► keys / addrpolicy
                                │                │
                                │                └──► nat ──► portmap
                                │
                                ├──► endpoint ──► addrpolicy
                                ├──► tunnel ◄──── connmgr
                                └──► pathinfo / fw / diag
```

`lib.rs` 只做聚合与再导出，不含逻辑。**任何模块不得反向依赖 `bin/`**；
`commands/*` 只依赖 `lib` 内的其它模块，可被集成测试直接调用。

---

## 5. 关键类型与函数契约

### 5.1 `config.rs`

```rust
/// 对外公布哪些地址。默认 RelayOnly（iroh 标准模型）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishPolicy {
    /// 只公布 relay URL —— 保证建连 + 打洞迁移（默认）
    RelayOnly,
    /// 只公布公网 IP —— 需要对端做端口转发/静态映射时用
    IpOnly,
    /// relay + IP 全公布
    All,
}

impl PublishPolicy {
    /// 解析 CLI 值 / 环境变量值
    pub fn parse(s: &str) -> Option<Self>;
    /// 映射到 iroh 的地址过滤器
    pub fn to_addr_filter(self) -> AddrFilter;
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub key_file: PathBuf,          // 默认 %APPDATA%\iroh-rdp-tunnel\server.key
    pub rdp_target: SocketAddr,     // 默认 127.0.0.1:3389
    pub publish: PublishPolicy,     // 默认 RelayOnly
    pub relay_mode: RelayMode,      // 默认 Default；NO_RELAY=1 → Disabled
    pub allow_list: Vec<EndpointId>,// 空 = 不限制
    pub listen_v6: bool,            // 默认 false（本机无 IPv6 全局地址）
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub remote: EndpointId,
    pub listen: SocketAddr,         // 默认 127.0.0.1:13389
    pub relay_mode: RelayMode,
}
```

配置优先级：**CLI 参数 > 环境变量 > 默认值**。

| 环境变量 | 等价 CLI | 说明 |
|---|---|---|
| `IRT_PUBLISH` | `--publish relay\|ip\|all` | 发布策略 |
| `IRT_KEY_FILE` | `--key-file` | 密钥路径 |
| `IRT_RDP` | `--rdp` | 被控端本地 RDP 地址 |
| `IRT_LISTEN` | `--listen` | 控制端本地监听 |
| `IRT_RELAY` | `--relay <url>` | 自建 relay（可重复） |
| `NO_RELAY` | `--no-relay` | 完全禁用 relay（旧名保留） |
| `IRT_ALLOW` | `--allow <id>` | 白名单（可重复，旧名保留） |

### 5.2 `keys.rs`

```rust
/// 读取密钥文件；不存在则原子创建（先写临时文件再 rename）。
/// 文件内容为 32 字节原始私钥；权限尽力设为 0600（Windows 跳过）。
pub fn load_or_create_secret_key(path: &Path) -> anyhow::Result<SecretKey>;

/// 把 endpoint id 以十六进制写一份同名 `.txt` 便于复制（best-effort）。
pub fn write_endpoint_id_hint(path: &Path, id: EndpointId) -> anyhow::Result<()>;
```

### 5.3 `nat.rs`

```rust
/// NAT 映射行为分类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingBehavior {
    /// 端点无关映射（EIM）：公网端点稳定 —— 打洞有利
    EndpointIndependent,
    /// 对称 NAT：映射随目标变化 —— 通告端点对不上号，打洞必败
    Symmetric,
    /// 无法判定
    Unknown,
}

#[derive(Debug, Clone)]
pub struct NatProfile {
    pub global_v4: Option<SocketAddrV4>,
    pub global_v6: Option<SocketAddrV6>,
    pub mapping: MappingBehavior,
    pub udp_v4: bool,
    pub udp_v6: bool,
    pub captive_portal: Option<bool>,
    pub preferred_relay: Option<RelayUrl>,
    pub relay_latencies: Vec<(RelayUrl, Duration)>,
    pub port_mapping: PortMappingStatus,
}

/// 从 iroh 的 net_report 解析 NAT 画像。
pub fn profile_from_report(report: &NetReport, pm: PortMappingStatus) -> NatProfile;

/// 给出「是否预期能 P2P 直连」的判定与理由。
pub fn verdict(profile: &NatProfile) -> Verdict;
```

判定逻辑：

| 条件 | 结论 |
|---|---|
| `mapping == Symmetric` | ❌ 直连不可行，只能中继 |
| `mapping == EndpointIndependent` | ✅ 直连可行（打洞走双方同时发包，不依赖放行任意入站） |
| `mapping == Unknown` | ⚠️ 未知，建议先跑 `diag` |

> **诚实边界**：iroh 的 net_report **只能测映射行为，不能测过滤行为**。「地址依赖过滤」这一项无法由 iroh 直接测量，`diag` 会明确标注「未测量」并指向 `netdiag/filter-proof.js` 做严格验证——不会假装测到了。

### 5.4 `portmap.rs`

```rust
pub enum PortMappingStatus {
    /// 三种协议均不可用（本机光猫实测如此）
    Unsupported,
    /// 部分可用
    Partial { upnp: bool, nat_pmp: bool, pcp: bool },
    /// 已成功建立映射
    Mapped { external: SocketAddrV4 },
    /// 探测失败
    ProbeFailed(String),
}

/// 独立跑一次 UPnP / NAT-PMP / PCP 探测（用 portmapper crate）。
pub async fn probe() -> PortMappingStatus;
```

### 5.5 `pathinfo.rs`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// 直连 IP 路径
    Direct,
    /// 经中继转发
    Relay,
}

/// 当前选中的路径快照。
#[derive(Debug, Clone)]
pub struct PathInfo {
    pub kind: PathKind,
    pub remote: String,            // "171.37.192.67:34622" 或 relay url
    pub rtt: Option<Duration>,
}

/// 读取连接当前选中的路径。
pub fn describe_path(conn: &Connection) -> Option<PathInfo>;

/// 订阅路径事件，路径切换时回调（用于「✅ 已切换到直连」提示）。
pub fn spawn_path_monitor(conn: Connection, on_change: impl Fn(PathInfo) + Send + 'static);
```

### 5.6 `tunnel.rs`（两端共用）

```rust
/// server 侧：QUIC stream ↔ 本地 TCP。
pub async fn bridge_quic_to_tcp(
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    tcp: tokio::net::TcpStream,
);

/// client 侧：本地 TCP ↔ QUIC stream。
pub async fn bridge_tcp_to_quic(
    local: tokio::net::TcpStream,
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
);
```

两函数共享一份双向拷贝 + 半关闭（half-close）收尾逻辑，抽成内部 `pump()`。

### 5.7 `connmgr.rs`（client 侧）

```rust
/// 维护一条到远端的常驻 QUIC 连接，断线自动重连。
pub struct ConnManager {
    remote: EndpointId,
    endpoint: Endpoint,
    conn_rx: tokio::sync::watch::Receiver<Option<Connection>>,
}

impl ConnManager {
    /// 启动后台任务：连接 → 断开 → 退避重连。
    pub fn start(endpoint: Endpoint, remote: EndpointId) -> Self;
    /// 取当前可用连接；没有则等待（最多 timeout）。
    pub async fn connection(&self, timeout: Duration) -> anyhow::Result<Connection>;
}
```

### 5.8 `fw.rs`

```rust
/// 为指定可执行文件添加 Windows 防火墙入站 UDP 放行规则。
pub fn install_udp_allow_rule(exe: &Path, rule_name: &str) -> anyhow::Result<()>;
/// 删除规则。
pub fn remove_rule(rule_name: &str) -> anyhow::Result<()>;
/// 检测当前 exe 是否已有放行规则。
pub fn has_allow_rule(exe: &Path, rule_name: &str) -> bool;
```

非 Windows 平台返回「不适用」错误，不 panic。

### 5.9 `endpoint.rs`

```rust
/// 地址发布 / 解析方式。
pub enum Discovery { Public, Disabled }

/// 中继连接的 TLS 信任。
/// —— 用「传入 CA 配置」而不是「跳过校验」：
///    iroh-relay 的 insecure_skip_verify() 受 test-utils feature 门控，
///    生产构建里不存在；而且跳过校验本身是安全陷脚。
pub struct EndpointOptions {
    pub secret_key: Option<SecretKey>,
    pub relay_mode: RelayMode,
    pub publish: PublishPolicy,
    pub discovery: Discovery,
    pub portmapper: bool,
    pub ca_tls_config: Option<CaTlsConfig>,
}

/// 按选项绑定一个 iroh 端点（server 用；含 pkarr 发布 + DNS 解析）。
pub async fn bind(opts: EndpointOptions) -> Result<Endpoint>;

/// 只解析、不发布（client 用；控制端不需要被拨通）。
pub async fn bind_resolver_only(opts: EndpointOptions) -> Result<Endpoint>;

/// 从 PEM 文件读取额外的根证书（信任自签证书的自建 relay）。
pub fn load_ca_file(path: &Path) -> Result<CaTlsConfig>;
```

---

## 6. CLI 契约

单一 `irt` 可执行文件，三个子命令：

```
irt server [--publish relay|ip|ipv6|all] [--key-file PATH] [--rdp ADDR]
            [--no-relay] [--relay URL]... [--allow ID]...
            [--no-discovery] [--ca-file PATH]
            [--install-firewall-rule] [--uninstall-firewall-rule]

irt client <ENDPOINT_ID> [--listen ADDR] [--no-relay] [--relay URL]...
                  [--no-discovery] [--ca-file PATH]
                  [--install-firewall-rule] [--uninstall-firewall-rule]

irt diag [--json]
```

分发时只有一个 `irt.exe`（Windows）或 `irt`（Linux/macOS）需要拷贝。
子命令定义集中在 `cli.rs`，实现集中在 `commands/*`，`bin/irt.rs` 仅 10 行左右。

---

## 7. 运行时输出样例

### 7.1 server 启动（实机输出）

```
=========================================================
 iroh-rdp-tunnel SERVER  (v0.2.0)
=========================================================
 endpoint id   : 1c46b334278b7ba001fed57d9000192b6994c198599fcfb14dc320054cfe9922
 密钥文件      : C:\Users\<你>\AppData\Roaming\iroh-rdp-tunnel\server.key
 发布策略      : relay
                 → 只公布 relay URL：客户端经 relay 建连后，
                   双方同时发包打洞，成功后自动迁移到直连
 RDP 目标      : 127.0.0.1:3389
 防火墙        : ⚠ 未检测到入站 UDP 放行规则
                → 请以管理员执行:  irt server --install-firewall-rule
                 （规则名: iroh-rdp-tunnel (irt UDP inbound)）
 接入白名单    : （未启用，任何 endpoint id 均可接入）
 中继          : https://aps1-1.relay.n0.iroh.link./
 本机公网端点  : 171.37.192.67:35839

 等待客户端连接…  (Ctrl-C 退出)
```

### 7.2 client 连接（关键验收信号，实机输出）

```
=========================================================
 iroh-rdp-tunnel CLIENT  (v0.2.0)
=========================================================
 远端 endpoint : 1c46b334…9922
 本地 TCP 监听 : 127.0.0.1:13389

 正在与远端建立连接…

 用系统自带的远程桌面连接本机端口:
     Windows : mstsc /v:127.0.0.1:13389
     Mac     : Microsoft Remote Desktop → 地址填 127.0.0.1:13389
     手机    : RD Client → 地址填 127.0.0.1:13389
 (Ctrl-C 退出)

 [路径·client] 中继  https://aps1-1.relay.n0.iroh.link./  RTT 1026ms
 [路径·client] ✅ 已切换到直连  171.37.192.67:35839  RTT 37ms
```

被控端同步输出：

```
 [路径·server] 中继  https://aps1-1.relay.n0.iroh.link./  RTT 622ms
 [路径·server] ✅ 已切换到直连  171.37.192.67:35839  RTT 1ms
```

### 7.3 `diag`（实机输出）

```
=========================================================
 iroh-rdp-tunnel 网络体检
=========================================================
 公网 IPv4 端点   : 171.37.192.67:35284
 公网 IPv6 端点   : （无全局地址）
 NAT 映射行为     : 端点无关映射 (EIM)  ✅ 公网端点稳定，可通告
 NAT 过滤行为     : 未测量（iroh 无法直接探测；严格验证见 netdiag/filter-proof.js）
                   → 但这不阻断直连：iroh 的打洞走「双方同时发包」
 UDP 可用         : IPv4 ✅   IPv6 ❌
 端口映射         : UPnP ❌  NAT-PMP ❌  PCP ❌（不支持）
                   → 不影响：EIM 映射下内端口固定即端点稳定，打洞不依赖端口映射

 实际 home relay : https://euc1-1.relay.n0.iroh.link./
 探测最快中继     : https://euc1-1.relay.n0.iroh.link./
                     https://euc1-1.relay.n0.iroh.link./  241ms
                     https://use1-1.relay.n0.iroh.link./  247ms
                     https://usw1-1.relay.n0.iroh.link./  432ms
                   （探测有 5 秒总超时，未列出的中继不代表不可达）

 判定: ✅ 具备 P2P 直连条件
   · 映射为 EIM（端点无关映射）⇒ 公网端点稳定，对端能对上号
   · iroh 的打洞走「双方同时发包」，不需要 NAT 放行任意来源的入站 UDP ⇒ 地址依赖过滤不阻断直连
   · UPnP / NAT-PMP / PCP 均不支持 ⇒ 不影响打洞（EIM 下内端口固定即端点稳定），仅损失「首包更快」的机会
 建议:
   1. server 保持默认 --publish relay
   2. 管理员执行 irt server --install-firewall-rule 放行入站 UDP
   3. 连接后看 client 输出是否出现「✅ 已切换到直连」
=========================================================
```

> 注：本机从中国到 n0 公共 relay 的延迟在 180–250ms（欧洲节点），
> 而直连国内是 37ms —— **这就是「必须打洞成功」的原因**。
> `aps1-1`（亚太）偶尔会被选中（约 190ms），但从本机看它连接不稳定。


---

## 8. 测试策略

| 层级 | 范围 | 手段 |
|---|---|---|
| 单元 | `config` 解析优先级、`keys` 往返、`PublishPolicy→AddrFilter`、`MappingBehavior` 判定文案、`PathInfo` 分类 | `cargo test`，纯函数无 IO |
| 集成 | 真实 iroh 端到端：进程内 relay（`iroh::test_utils::run_relay_server()`）+ server + client + 内存 TCP 回环 | `tests/e2e.rs`，dev-dependency 开 `iroh/test-utils` |
| 手工 | 真实公网 P2P 直连验证 | 手机 4G/5G 或境外主机连 client，观察「✅ 已切换到直连」 |

集成测试要点：
1. 用进程内 relay 替代 n0 公网 relay，测试不依赖外网；
2. server 用 `NO_RELAY` 之外的方式指定自建 relay（`--relay` / `RelayMode::custom`）；
3. 断言：随机字节经 TCP → QUIC → TCP 后**逐字节一致**（RDP 协议对完整性敏感）；
4. 断言：连接建立后 `describe_path()` 返回 `Some(_)`，路径类型可判定。

---

## 9. 风险与回退

| 风险 | 影响 | 缓解 |
|---|---|---|
| 改了发布策略后仍走中继 | 延迟 40ms → 200ms+ | 运行时明确打印路径类型；`--publish all` 可强制先试直连；对比测试 |
| Windows 防火墙规则依赖管理员 | 规则装不上 | 启动时检测并给出**可直接复制粘贴**的命令行 |
| `iroh` 升级破坏 API | 编译失败 | 锁定 `iroh = "1.0"`（`Cargo.lock` 已锁 1.0.2）；`unstable-net-report` 为 feature，可随时摘掉 |
| `portmapper` 额外依赖 | 编译时间/体积 | 已是 iroh 传递依赖，不新增下载；探测失败降级为「未知」不报错 |
| 单一入口破坏旧的 `server.exe`/`client.exe` 用法 | 老脚本失效 | README 顶部给出迁移说明；旧环境变量继续生效 |

---

## 10. 实施顺序

1. **M1 骨架**：模块划分 + `cli`（单一 `irt` 入口 + 三子命令）+ `config` / `keys` / `addrpolicy` + 单元测试
2. **M2 连通性**：发布策略改 relay-only + server 持久化 id + client 常驻连接（`connmgr`）+ `tunnel` 抽取
3. **M3 可观测**：`pathinfo` + server/client 双端路径打印（直连/中继 + RTT + 迁移提示）
4. **M4 防火墙**：`fw` + `--install-firewall-rule` + 启动自检提示
5. **M5 体检**：`nat` + `portmap` + `irt diag` + JSON 输出
6. **M6 文档**：README 重写（实测网络画像 / 机制说明 / 排障决策树）+ DESIGN 同步
7. **M7 验证**：`cargo test` + 集成测试 + 真实公网 P2P 验收

---

## 10.5 评审修复（分支末端评审发现的问题）

整分支评审发现 4 个阻塞项与若干重要项，全部已修：

| 编号 | 问题 | 修复 |
|---|---|---|
| C1 | `irt server --no-relay` 永久挂起、连 endpoint id 都不打印（`online()` 在 `RelayMode::Disabled` 下永不返回） | banner 拆成「立即打印」与「网络信息」两段；`online()` 加 15 秒超时；`RelayMode::Disabled` 直接跳过等待 |
| I1 | 防火墙自检 100% 误报（netsh 非 verbose 无程序行 + 标签本地化） | 改用 `verbose`；按**路径**匹配整段输出；查全部规则（覆盖 Windows 自动创建的规则）；新增 `FirewallStatus::NotApplicable` |
| I2 | `irt diag` 在 relay 不可达时无限挂起 | `online()` 与端口映射探测都加超时 |
| I3 | client 不打印自身 endpoint id，`--allow` 白名单实际不可用 | client 也持久化私钥（默认 `client.key`）并打印「本机 endpoint」；`ConnManager` 支持显式指定远端地址 |
| I4 | 大写十六进制 endpoint id 解析失败 | 解析前统一转小写（`parse_endpoint_id`） |
| I5 | 「未知」被渲染成硬失败（❌） | 新增 `Expectation` 枚举，`Unknown` 单独渲染成 ⚠️ |
| I6 | `ConnManager` 可能返回已死连接 | `connection()` 跳过 `close_reason()` 非空的连接；`open_bi` 失败重试一次 |
| I7 | Windows 上 `rename` 覆盖导致并发启动时 endpoint id 不固定 | 改用 `hard_link`（目标已存在则失败 → 读磁盘上那份）；临时文件名加进程内唯一序号 |
| I8 | e2e 注释与实现不符，client 侧桥接零覆盖 | 抽出 `commands::client::serve_local`；新增 `client_local_tcp_path_roundtrips` 用例，走**与生产完全相同**的路径 |
| I9 | RDP 拨号失败会拆掉整条 QUIC 连接 | 改为只 `reset` 当前这一条流 |
| M4 | 「本机公网端点」标签把所有网卡地址都叫公网 | 改为「本机地址」并区分 (公网)/(私网) |
| M6 | `mapping_varies_by_dest()` 把 v4/v6 用 `||` 合并 | 改为优先看 IPv4 |
| M15 | 桥接一侧出错时另一侧一直挂着 | 改为 `select!`：一侧出错立即结束另一侧；EOF 半关闭语义保持不变 |

---

## 11. 非目标（本次不做）

- 自建 relay / ID 服务器（iroh 已提供 n0 公共 relay；自建方案在 README 里给出配置方法即可）
- Windows 服务化 / 开机自启
- 多客户端并发授权、屏幕录制、文件传输
- IPv6 直连优化（本机无 IPv6 全局地址）
