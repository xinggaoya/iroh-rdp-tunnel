# iroh-rdp-tunnel

一个最小化的 **P2P RDP 远程桌面隧道**：基于 [iroh](https://github.com/n0-computer/iroh) 在两端建立 QUIC 连接，把控制端的本地 TCP 端口直接桥到被控端的 Windows RDP 服务（3389）。

**实际使用仍然使用系统自带的远程桌面工具**（mstsc / 移动端 RD Client / macOS Microsoft Remote Desktop），不需要安装任何额外的客户端软件。

> **v0.3：两个传输后端**
>
> v0.2 只能用 iroh，而 iroh 的打洞候选**只**来自中继观测到的端点 ——
> 在**对称 NAT**（映射随目标变化）下必然对不上号，打洞**永远**打不通。
> v0.3 加了第二个后端 [rustp2p-quic](https://github.com/rustp2p/rustp2p)，
> 它用「端口预测 + 全局随机扫描」正面破对称 NAT。
>
> | | `--transport iroh`（默认） | `--transport rustp2p` |
> |---|---|---|
> | **一定能连上吗** | ✅ 一定能（走中继） | ❌ 不一定 —— **打洞成功前连不上** |
> | **能直连吗** | ❌ 对称 NAT 下永远不能 | ✅ 能（实测 205ms） |
> | 延迟 | 高（实测 1200ms） | 低 |
> | 需要自建服务器 | 否 | 是（VPS 上一个 node 即可） |
> | 怎么选 | **保底**：先保证 RDP 能用 | **争取直连**：延迟敏感时用 |
>
> ⚠️ **rustp2p 的中继兜底与 iroh 不是一回事** ——
> rustp2p 的中继是**协议层转发**，QUIC 流的建立仍需要一条已确认的路由，
> 所以**打洞成功前它是连不上的**。详见「rustp2p 后端」一节。
>
> **v0.2 与旧版的差异**
>
> | | 旧版 | v0.2 |
> |---|---|---|
> | 可执行文件 | `server.exe` / `client.exe` 两个 | 单一 `irt.exe`，三个子命令 `server` / `client` / `diag` |
> | endpoint id | 每次启动都变 | **持久化到文件，永久固定** |
> | 地址发布 | 只公布公网 IP（relay URL 被剔除） | **只公布 relay URL**（iroh 标准模型，见下方「网络机制」） |
> | 连接路径 | 不可见 | **实时显示「直连 / 中继」+ RTT**，路径迁移时提示「✅ 已切换到直连」 |
> | 防火墙 | 文档里提一句 | 内置 `irt server --install-firewall-rule` + 启动自检 |
> | 网络体检 | 无 | 内置 `irt diag`：NAT 画像 + 直连可行性判定 |

---

## 快速开始

### 1. 编译

```bash
# Windows
cargo build --release
# 产物：target\release\irt.exe

# Linux / macOS 交叉编译 Windows 版本
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

### 2. 在被控的 Windows 机器上启动 server

```powershell
.\irt.exe server
```

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

把 `endpoint id` 复制下来（微信 / 邮件 / 抄在本子上都行）。

> **endpoint id 固定不变**：私钥存在 `%APPDATA%\iroh-rdp-tunnel\server.key`，重启后 id 一样。
> 想换 id，删掉这个文件重新启动即可。

> ⚠ **防火墙那一步别跳过**。iroh 走 UDP，Windows 防火墙默认拦截未放行的入站 UDP，
> 不放行的话打洞永远不成功、只能退回中继。用**管理员** PowerShell/CMD 执行一次：
>
> ```powershell
> .\irt.exe server --install-firewall-rule
> ```

### 3. 在控制端启动 client

```powershell
.\irt.exe client 1c46b334278b7ba001fed57d9000192b6994c198599fcfb14dc320054cfe9922
```

```
=========================================================
 iroh-rdp-tunnel CLIENT  (v0.2.0)
=========================================================
 远端 endpoint : 1c46b334278b7ba001fed57d9000192b6994c198599fcfb14dc320054cfe9922
 本机 endpoint : 49e7105bec4160af91e110c07f7f09b696d01830990910cb3e2e76e01cc43af2
                 （可写进被控端的 --allow 白名单）
 本地 TCP 监听 : 127.0.0.1:13389

 正在与远端建立连接…

 用系统自带的远程桌面连接本机端口:
     Windows : mstsc /v:127.0.0.1:13389
     Mac     : Microsoft Remote Desktop → 地址填 127.0.0.1:13389
     手机    : RD Client → 地址填 127.0.0.1:13389
 (Ctrl-C 退出)
```

> 控制端的私钥也持久化（默认 `%APPDATA%\iroh-rdp-tunnel\client.key`），
> 所以**本机 endpoint** 是固定的 —— 想加白名单就把这一串填到被控端的 `--allow` 里。

### 4. 用系统自带的远程桌面连接

```powershell
mstsc /v:127.0.0.1:13389
```

凭据填**被控端 Windows 的本机账户用户名 + 密码**。

### 5. 看连接路径 —— 这是验收信号

连上之后，控制端会打印：

```
 [路径·client] 中继  https://aps1-1.relay.n0.iroh.link./  RTT 1026ms
 [路径·client] ✅ 已切换到直连  171.37.192.67:35839  RTT 37ms
```

- 出现 **「✅ 已切换到直连」** ⇒ 打洞成功，全程 P2P，延迟跟裸连一样。
- 一直停在 **「中继」** ⇒ 打洞没成功，流量全走中继（延迟会明显变高）。

被控端也会同步打印同样的路径信息。

---

## 网络机制：为什么默认只公布 relay URL

这是本项目最核心的一个设计决策，值得说清楚。

### 打洞是怎么发生的

iroh 的打洞基于 **QUIC NAT Traversal 扩展**（[draft-seemann-quic-nat-traversal-02](https://www.ietf.org/archive/id/draft-seemann-quic-nat-traversal-02)）：

1. 先建立一条 QUIC 连接（走 relay，或直连）；
2. **在这条已建立的连接上**双方交换自己的 NAT 候选地址；
3. 双方**同时**向对方的候选地址发包 ⇒ NAT 上对应的洞被打开；
4. 直连路径验证通过后，连接自动迁移过去，relay 退出。

对照 iroh 1.0.2 源码：

| 事实 | 源码位置 | 含义 |
|---|---|---|
| 打洞触发点 = 连接建立之后 | `socket/remote_map/remote_state.rs` `do_holepunching()` | **先建连，才能打洞** |
| 候选地址在已建立的连接上交换 | `conn.initiate_nat_traversal_round()` | 需要一条能通的控制通道 |
| relay 路径必须来自**对端公布的 RelayUrl** | `remote_state.rs` `TransportAddr::Relay(url) => Addr::from((url, endpoint_id))` | **不公布 relay URL ⇒ 客户端连初始连接都建不起来** |
| 直连优先于中继 | `socket/biased_rtt_path_selector.rs`：IPv4/IPv6 是 primary 层，Relay 是 backup 层，跨层立即切换 | 公布 relay URL **不会**导致「一直走中继」 |

### 于是

```
server 公布 relay URL（iroh 标准模型）
  → 客户端经 relay 建连（必定成功）
  → 已建立的连接上交换 NAT 候选地址
  → 双方同时发包 → 打洞成功 → iroh 立即切到直连路径
  → 之后全程直连，中继只做兜底
```

这正是「**双方同时发包**」的打洞模式 —— iroh 原生就实现了，不需要自己造。

> 旧版默认的 `AddrFilter::ip_only()` 会把 relay URL 从 pkarr 记录里剔掉，
> 客户端因此建不出 relay 路径，只能直连公网 IP；
> 而在**地址依赖过滤**的 NAT 后面这必然失败 —— 也就没有通道去交换打洞候选，
> 直连永远不可能发生。v0.2 把默认值改了回来。

### 一个更隐蔽的坑：两个 publisher 抢同一个 key

旧版用的是 `Endpoint::builder(presets::N0)`，然后又追加了
`.address_lookup(PkarrPublisher::n0_dns().addr_filter(ip_only()))`。

问题在于 iroh 的两个默认值：

| 事实 | 源码位置 | 后果 |
|---|---|---|
| `Builder::address_lookup()` 是**追加**不是替换 | `endpoint.rs:605` `self.address_lookup.push(...)` | 端点上挂了**两个** publisher |
| `PkarrPublisherBuilder::new()` 的默认过滤器是 `AddrFilter::relay_only()` | `address_lookup/pkarr.rs:168` | publisher #1 只发 relay URL |

两个 publisher 写**同一个 endpoint id 的同一条 pkarr 记录**，后写覆盖先写：

- publisher #1（`presets::N0` 自带）→ 记录里只有 `relay=...`
- publisher #2（追加的 `ip_only`）→ 记录里只有 `ip=...`

pkarr 的重发布间隔是 **5 分钟**（`DEFAULT_REPUBLISH_INTERVAL`），TTL 30 秒。
也就是说这条记录会**在两种形态之间来回翻**，客户端解析到哪种全看运气 ——
拿到只有 IP 的那次，就必然超时。

v0.2 的做法：**不用 `presets::N0`**，改用 `presets::Minimal` +
**唯一一个** `PkarrPublisher`，过滤策略由 `--publish` 决定：

```rust
builder = builder
    .address_lookup(PkarrPublisher::n0_dns().addr_filter(opts.publish.to_addr_filter()))
    .address_lookup(DnsAddressLookup::n0_dns());   // 只解析、不发布
```

实测（`dns.iroh.link` 上的真实记录）：

```
_iroh.<z32>.dns.iroh.link  TXT  "relay=https://use1-1.relay.n0.iroh.link./"
```

一条记录、一种形态、始终带 relay URL。客户端用 `irt diag --lookup <id>` 可随时复查。

### 直连优先，但中继永远兜底

iroh 默认的路径选择器把 IPv4/IPv6 放在 primary 层、relay 放在 backup 层，
**跨层切换是立即的**。所以公布 relay URL 不会带来「一直走中继」的副作用 ——
只要打洞成功，连接会立刻切到直连。

---

## 本机实测网络画像

> 2026-11-06 在本机（联通 10G-GPON 光猫 `192.168.1.1`）实测，`irt diag` 可复现。

| 项目 | 实测结果 | 对实现的影响 |
|---|---|---|
| 公网 IP | `171.37.192.67` | 可作为通告端点 |
| NAT **映射**行为 | **EIM 端点无关映射** | 公网端点稳定 → 可通告、可打洞 |
| NAT **过滤**行为 | **地址依赖**：未通信来源的入站 UDP 全丢 | **必须双方同时发包**（iroh 默认即是） |
| CGNAT | 无 | 打洞成立的前提条件已满足 |
| UPnP / NAT-PMP / PCP | **三者全不支持** | 端口映射不可依赖，但 EIM 下不需要 |
| IPv6 | 无全局地址（仅 `fe80::`） | 只走 IPv4 |
| 延迟 | 国内 37ms / 0 丢包 | 直连体验远好于中继 |
| 带宽 | 国内 ~51 Mbps；境外 ~6 Mbps | 跨洋时中继反而可能更顺 |
| Windows 防火墙 | 程序默认**无入站放行规则** | 必须自行放行（`irt server --install-firewall-rule`） |
| RDP | 已开启，监听 3389 | 可直接用 |

---

## `irt diag`：网络体检

```powershell
.\irt.exe diag
```

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

`irt diag --json` 输出同内容的 JSON，便于脚本处理。

### 关于「NAT 过滤行为：未测量」

iroh 的 net report **只能测映射行为，测不了过滤行为**。`irt diag` 如实标注「未测量」，
不会编造结论 —— 而且这不影响判断：iroh 的打洞走双方同时发包，
本来就不需要 NAT 放行任意来源的入站。

要严格验证过滤行为，可以用 `netdiag/filter-proof.js` 那套脚本（需要外部 STUN 资源）。

### `irt diag --lookup`：查对端公布了什么

```powershell
.\irt.exe diag --lookup 1a4172f599783632000f88cac5f11ec0b5bc164c0aa43e1e94ceb4f8e436366c
```

```
=========================================================
 iroh-rdp-tunnel 对端公布地址查询
=========================================================
 endpoint id   : 1a4172f599783632000f88cac5f11ec0b5bc164c0aa43e1e94ceb4f8e436366c
 公布的中继     :
                 https://euc1-1.relay.n0.iroh.link./
 公布的 IP     : （无）

 判定: ✅ 客户端能连上
   · 记录里含 relay URL：客户端可以经中继建连，必然可用
   · 只公布了 relay URL（relay-only 策略）：直连需要双方同时发包打洞，成功前流量走中继
 建议:
   1. 中继延迟高？用 --relay 指定更近的中继
=========================================================
```

查的是**与 iroh 客户端完全相同**的解析路径（`_iroh.<z32>.dns.iroh.link` 的 TXT 记录），
所以看到的就是客户端会拿到的东西。判定规则：

| 对端公布的记录 | 客户端能走的路 | 后果 |
|---|---|---|
| 含 relay URL | 中继路径（+ 可能打洞） | ✅ 一定能连上 |
| 只有 IP | 只能直连 | ⚠ NAT 过滤（家宽光猫常见）会丢首包 → 必然超时 |
| 什么都没有 | 无 | ❌ 连不上 |

**这是「client 连不上」时最该先跑的一条命令** —— 它能一步区分「网络不通」和「对端没公布中继地址」。

---

## 实战排障：三个真实踩过的坑

下面三条都是实际调试中真实遇到并定位到的，按「出现频率」排序。

### 坑 1：两端用了不同的中继 ⇒ RTT 翻倍

**症状**：连上了，但 RDP 巨卡；路径 RTT 高达 1152ms。

**原因**：两端各自自动选 relay，很容易选到不同家。流量要先到**本端**的中继，
再由它转发到**对端**的中继（多一跳），延迟直接叠加。

```
[路径·client] ⚠ 路径经由 https://euc1-1.relay.n0.iroh.link./ 中转，
                但本端连的是 https://usw1-1.relay.n0.iroh.link./ —— 多了一跳中继转发
```

**修法**：两端显式指定**同一个** relay：

```powershell
.\irt.exe server --relay https://aps1-1.relay.n0.iroh.link./
.\irt.exe client <id> --relay https://aps1-1.relay.n0.iroh.link./
```

**验证**：A 机 banner 的 `中继 :` 与 B 机 banner 的 `本端中继 :` 必须完全相同。

> `RelayMode::custom()` 是**独占**模式 —— 指定了就不可能选到别的中继。
> 所以只要两端显示的不一样，就一定有一端没指定。

### 坑 2：对端 NAT 映射随目标变化（非 EIM）⇒ 打洞必败

**症状**：连接建立（走中继），但永远等不到「✅ 已切换到直连」。

**原因**：客户端日志里的
`IPv4 address detected by QAD varies by destination` —— iroh 内部对应
`mapping_varies_by_dest_ipv4 = Some(true)`（`net_report/report.rs:95`），
含义是**同一个本地端口连不同目标，公网映射端点会变**。

为什么这在数学上无解：

| 环节 | 事实 | 源码位置 |
|---|---|---|
| 1 | iroh 通告的候选 = 「**对中继**观测到的公网端点」 | `socket.rs:1838` `DirectAddrType::Qad` |
| 2 | 对中继的映射是 `public_ip:P_relay`，对服务器的映射是 `public_ip:P_server`，两者不等 | — |
| 3 | 服务端按通告的候选打过去 → 客户端 NAT 查表落空 → 丢包 | `remote_state.rs` `do_holepunching()` |

**修法**（只能改对端那一侧，iroh 这边无解）：

- **对端做端口映射** —— 把内网 UDP 端口固定转发出去，映射就与目标无关了 ⇒ 变回 EIM
- **对端换网络** —— 手机热点 / 4G，多数运营商给的是 EIM
- **对端开通 IPv6**（见坑 3）—— 根本不需要 NAT 遍历

### 坑 3：只有一端有 IPv6 ⇒ 直连被 NetworkUnreachable 直接掐死

**症状**：服务端日志里

```
poll_send{network_path=Ip { remote: [2408:845d:102:6406:...]:56428, local: None }}
  sendmsg error: 10051 NetworkUnreachable
```

**原因**：`local: None` = **本机没有 IPv6 源地址**，发不出 IPv6 包。

**这其实是最好的解法**：IPv6 直连**根本不需要 NAT 遍历**。
只要两端都有全局 IPv6，直接就通，延迟约 37ms。

- 客户端本来就有 IPv6（`2408:845d:102:6406:...`）
- 服务端需要在光猫/路由器上开通 IPv6（联通 10G-GPON 光猫通常支持，只是可能没下发到内网）
- **开通后无需改任何参数** —— IPv6 候选是在已建立的连接上交换的，
  与 `--publish` 策略无关

### 坑 4：只给被控端装了防火墙规则 ⇒ 控制端的防火墙把打洞包挡了

**症状**：被控端显示「防火墙 ✅ 已放行入站 UDP」，控制端一切正常，
但两端都等不到「✅ 已切换到直连」，而且**连「🔓 公网直连路径已打开」都没有**。

**原因**：打洞要**双向**：

```
服务端 ──入站 UDP──▶ 控制端的 NAT 映射端口 ──▶ 控制端的 Windows 防火墙 ──▶ 应用程序
```

被控端（服务端）的入站包要穿过**控制端**的防火墙。
很多人只在被控端装了规则（因为被控端要对外「被拨通」），
却忘了控制端也要放行**入站 UDP** —— 打洞包正是入站。

**修法**：**两端都装**（同一个 exe，一条规则两边都覆盖）：

```powershell
# 被控端
.\irt.exe server --install-firewall-rule
# 控制端（同样要装！）
.\irt.exe client --install-firewall-rule
```

新版两端 banner 都会显示防火墙状态：

```
 防火墙        : ✅ 已放行入站 UDP
                 （规则名: iroh-rdp-tunnel (irt UDP inbound)）
```

> 补充：打洞能不能成，最终取决于**对端的过滤行为** ——
> **ADF**（地址依赖，只看源 IP）可以成，**APDF**（地址+端口都依赖）才没戏。
> 绝大多数家用/办公 NAT 都是 ADF，所以先把防火墙排掉再谈别的。

### 坑 5：net report 还没就绪就建连 ⇒ 客户端通告的候选里没有公网地址

**症状**：两端都正常、连接也建立了，但服务端**连一条 IPv4 打洞包都不发** ——
连「🔓 公网直连路径已打开」这一行都不会出现。

**原因**：QUIC NAT Traversal 的角色分工是（`noq/connection.rs:857`）：

> **servers** send these addresses to clients in `ADD_ADDRESS` frames …
> **Clients** provide their own reachable addresses in `REACH_OUT` frames
> when `initiate_nat_traversal_round()` is called.

也就是说**客户端**要用 `REACH_OUT` 通告自己的可达地址，服务端才知道往哪儿打。
而客户端的公网候选（`global_v4`）**来自 net report 的 QAD 探测** ——
net report 要连上 relay、跑完多个中继的对比才出结果，**实测比连接建立晚 24~47 秒**：

```
06:39:39  已与远端建立连接                                        ← 连接建立
06:40:03  IPv4 address detected by QAD varies by destination      ← 24 秒后才有公网端点
```

在它就绪之前，客户端通告的候选里**只有私网地址**，服务端拿到的远端候选
要么为空、要么是根本打不通的私网地址 —— 于是连尝试都不会有。

**修法**：**两端都在接受/发起连接之前先等 net report 就绪**（`NET_REPORT_TIMEOUT`，默认 25 秒）。

```
[路径·server] 🔓 公网直连路径已打开  ip:171.37.192.67:36419
```

出现这行就说明打洞真的开始了。

> 副作用：server / client 启动会慢几秒（要等 QAD 探测跑完）。
> 对 RDP 隧道完全无影响 —— 反正你也要等 mstsc 连上才能用。

### 坑 6：iroh 1.0.2 的打洞候选**只能**来自 QAD ⇒ 对称 NAT 无解

这是整条调试链的**最终结论**，也是很多人在 iroh 上卡住的原因。

**iroh 1.0.2 通告给对端的可达地址，只有 QAD 一个来源** —— 即
「从中继观测到的公网端点」（`socket.rs:1838` `DirectAddrType::Qad`）。

于是在**映射随目标变化**（ADM/对称）的 NAT 后面：

| 映射 | 端口 |
|---|---|
| 客户端 → 中继 | `public_C:P_relay` ← iroh 通告的就是这个 |
| 客户端 → 服务端 | `public_C:P_server` ← 真正能通的是这个 |

`P_relay ≠ P_server` ⇒ 服务端按通告的端点打过去 ⇒ 客户端 NAT 查表落空 ⇒ 丢包。

> QUIC 本身有 **observed address** 传输参数，正是为这个场景设计的
> （noq 的文档原话：*"can aid the current endpoint in inferring its reachable
> address, which in most NAT'd networks will not be easily available to it"*）。
> 但 **iroh 1.0.2 内部既没有启用、也没有对外暴露**它
> （`Role` 派生了 `Default` ⇒ `send=false, receive=false`；iroh 的
> `endpoint/quic.rs` 里只有 builder 方法，默认 transport config 不打开）。
> 所以这条纠错链路在 iroh 上暂时用不上。

**唯一能打破的办法：让映射与目标无关。**

| 手段 | 效果 |
|---|---|
| 路由器上固定转发本机 UDP 端口 | 公网端口不再随目标变化 ⇒ 变回 EIM ⇒ 打洞可成 |
| 启用 UPnP / NAT-PMP / PCP | 同上（本工具会自动尝试申请） |
| 换网络（手机热点 / 4G） | 多数运营商给的是 EIM |

`irt diag` 的 `端口映射` 一行就是在测这个。**在**控制端**跑 `irt diag`**：
若 UPnP ✅，iroh 会自动申请端口映射 ⇒ 对称 NAT 被破解 ⇒ 直连可成。

### v0.3 的解法：rustp2p 后端

既然 iroh 破不了对称 NAT，v0.3 就换了个**用端口预测破局**的传输层：
[rustp2p-quic](https://github.com/rustp2p/rustp2p)（Apache-2.0）。

它的做法是：

1. 通过 STUN 观测自己的**公网映射端口集合**，算出「端口分配范围」
   （对称 NAT 下这个范围可能高达几万个端口）；
2. 打洞时先用**端口预测**猜对端可能用的端口；
3. 猜不中就**全局随机扫描**（每轮 1200~1500 个端口，持久游标）；
4. 辅助 socket（assistant sockets）增加映射端口的散布范围。

**实测（同一台机器、同一网络、家宽为对称 NAT）**：

```
iroh    ：[路径·client] ⚠ 30 秒内未建立**公网**直连路径，当前走中继
rustp2p ：[路径·client] ✅ 已切换到直连  107.172.191.12:2525  RTT 200ms
```

#### 怎么用

需要一台**有公网 IPv4、UDP 可达**的 VPS 上跑一个 rustp2p 节点
（它同时当 bootstrap 与中继）。部署手册见
[`docs/deploy/rustp2p-node-vps.md`](docs/deploy/rustp2p-node-vps.md)。

```powershell
# 被控端（peer id 固定；白名单列出控制端的 peer id）
irt server --transport rustp2p --node-id my-server ^
           --allow-peer my-client ^
           --bootstrap <VPS_IP>:6888

# 控制端（peer id 固定）
irt client --transport rustp2p --peer my-server --node-id my-client ^
           --bootstrap <VPS_IP>:6888
```

> ⚠️ **两端必须用同一个「公网可达」的 bootstrap 地址**。
> 被控端若写 `--bootstrap 127.0.0.1:6888`（因为节点就在本机），
> 中继观测到的它的公网端点会是 `127.0.0.1:xxxxx` ⇒ 客户端永远打不到。

> ⚠️ **控制端必须用固定 peer id，被控端的 `--allow-peer` 才能匹配上它**。
>
> `--allow-peer` 有**两重**作用，缺一不可：
>
> 1. **接入白名单**：被控端在 accept 层按 peer id 过滤入站流
>    ⇒ 控制端的 peer id 必须与 `--allow-peer` 里写的**逐字相同**；
> 2. **打洞白名单**：rustp2p-quic 只有在 `punch_allowed(src)` 为真时
>    才回复 `PunchReply`，而对端正是靠这个 `PunchReply`
>    来确认自己的直连路由 ⇒ **不在名单里 ⇒ 直连永远建不起来**。
>
> ⇒ 控制端 peer id 随机生成时，被控端的 `--allow-peer` 必然匹配不上
> ⇒ **100% 握手超时**。所以要么两端都 `--node-id` 固定，
> 要么被控端**不要**写 `--allow-peer`。
>
> 实测：被控端白名单=[clientZ] 而控制端是 clientZ2 ⇒ 握手超时；
> 去掉被控端白名单 ⇒ **0.1 秒打通**，64KB 逐字节一致。

> ⚠️ **打洞是双向协议**，两端必须同时向对方打才可能打通。rustp2p 默认
> 会对 bootstrap 上**所有**已知 peer 打洞 —— 而那上面通常还挂着别的
> 客户端实例，于是对称 NAT 的端口空间（实测 3~6 万）被瓜分，
> 且打洞频率按 peer 分摊 ⇒ **目标 peer 永远打不通**。
>
> ⇒ 这正是**控制端**要把自己收敛到「只对目标 peer 打洞」的原因
> （`irt client` 已经内置，无需任何参数）。
>
> 实测：不限定时 600 秒打不通；收敛后 **30 秒打通**，
> 512KB 隧道逐字节一致、走直连 215ms。详见
> [`docs/deploy/rustp2p-node-vps.md` §3.4](docs/deploy/rustp2p-node-vps.md)。

**可用的环境变量**：`IRT_TRANSPORT` / `IRT_NODE_ID` / `IRT_PEER` /
`IRT_BOOTSTRAP` / `IRT_STUN` / `IRT_ASSISTANT_SOCKETS` / `IRT_ALLOW_PEERS`。

#### rustp2p 的两个限制（务必知道）

1. **打洞成功前连不上** —— 它的中继是协议层转发，QUIC 流仍需要已确认的路由。
   实测**配好白名单后**打洞约 **30 秒**；端口范围 3 万~6 万时可能更久。
   ⇒ **默认仍用 `--transport iroh` 保底**；需要低延迟时再切。
2. **身份是降级的** —— `PeerId` 是任意字符串、证书校验被跳过，
   `--allow-peer` 只是**字符串比对，不是认证**。别把它暴露在不可信网络上。

#### 网络体检

```powershell
irt diag --transport rustp2p
```

会额外给出**端口分配范围**（端口预测的候选空间）—— 这个数字直接决定
「直连要多久」：

```
 NAT 映射行为     : 对称 NAT（映射随目标变化）  🟡 端点对不上号，但 rustp2p 靠端口穷举可破
 对称端口范围     : 33655 个端口（端口预测的候选空间）
 判定: 🟡 直连有戏但要靠端口穷举 —— 打不成会自动回落到中继
```

### 顺带：两个可以忽略的告警

| 告警 | 含义 |
|---|---|
| `WSAEMSGSIZE (10040)` | Windows UDP 发送缓冲区偏小，只影响 **IPv6 QAD 探测**（1389 字节），不影响连通性 |
| `MultipathNotNegotiated` | 路径关闭时的良性告警 |

---

## 排障决策树

| 现象 | 排查顺序 |
|---|---|
| **client 连不上**（一直转圈） | 1. `irt server` 是不是还开着、id 抄对了吗<br>2. 被控端能上外网吗（`irt diag` 看公网端点）<br>3. 防火墙：被控端跑过 `irt server --install-firewall-rule` 吗<br>4. `irt diag --lookup <id>` —— 看**对端到底公布了什么**（只有 IP 没有 relay 就会必然超时） |
| **一直显示「中继」，没有「✅ 已切换到直连」** | 1. 防火墙规则装了吗（**最常见原因**）<br>2. 跑 `irt diag` 看映射行为是不是 EIM<br>3. 中继延迟高（>150ms）？换一个更近的 relay：`irt server --relay https://aps1-1.relay.n0.iroh.link./`<br>4. 对端也在 NAT 后面？**双方都要能打洞** |
| **首帧很慢，之后正常** | 打洞本身要几次往返，第一次连接会慢一些。第二次连接因为连接已建立会很快 |
| **mstsc 报「无法连接到 127.0.0.1:13389」** | client 没运行；或端口被占用；或本机防火墙拦了本地回环 |
| **rustp2p 后端连不上** | 1. 两端用的是**同一个公网** bootstrap 吗（被控端别写 `127.0.0.1`）<br>2. VPS 的端口在 1Panel 白名单里吗（tcp+udp 都要）—— 未放行会被**静默 DROP**<br>3. **两端都用固定 peer id 了吗？被控端 `--allow-peer` 列出控制端 id 了吗？**（不限定 ⇒ bootstrap 上其它实例分走端口空间 ⇒ 永远打不通）<br>4. 打洞可能要几十秒，看 client 输出里「打开到 xxx 的双向流等待超过 30 秒」<br>5. 等不及就切回 `--transport iroh` 保底 |
| **远端提示「本机 RDP 未在 127.0.0.1:3389 上运行」** | 被控端没启用 RDP：`reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f` |
| **远程桌面提示账户密码错误** | RDP 要求**被控端本机账户** + 密码；某些家庭版 / 简化账户请改成 Microsoft 账户 |
| **想禁止别人接入** | `irt server --allow <endpoint_id>`（可重复），或用 `IRT_ALLOW` 环境变量 |
| **中继太慢** | `irt server --relay <url>` 指定自建/更近的中继；自签证书用 `--ca-file <PEM>` 信任 |

---

## CLI 参考

```
irt server [--publish relay|ip|ipv6|all] [--key-file PATH] [--rdp ADDR]
            [--relay URL]... [--no-relay] [--allow ID]...
            [--no-discovery] [--ca-file PATH]
            [--install-firewall-rule] [--uninstall-firewall-rule]

irt client <ENDPOINT_ID> [--listen ADDR] [--relay URL]... [--no-relay]
                  [--no-discovery] [--ca-file PATH]
                  [--install-firewall-rule] [--uninstall-firewall-rule]

irt diag [--json]
irt diag --lookup <ENDPOINT_ID> [--json]
```

| 参数 | 说明 |
|---|---|
| `--publish` | 对外公布哪些地址。`relay`（默认，iroh 标准模型）/ `ip` / `ipv6` / `all` |
| `--key-file` | endpoint 私钥文件路径（默认 `%APPDATA%\iroh-rdp-tunnel\server.key`） |
| `--rdp` | 被控端本机 RDP 地址（默认 `127.0.0.1:3389`） |
| `--listen` | 控制端本地监听地址（默认 `127.0.0.1:13389`） |
| `--relay` | 自建 relay URL，可重复 |
| `--no-relay` | 完全禁用 relay（仅同一局域网） |
| `--allow` | 允许接入的 endpoint id 白名单，可重复 |
| `--no-discovery` | 不使用 n0 公共 pkarr / DNS |
| `--ca-file` | 额外的根证书文件（PEM），用于信任自签证书的自建 relay |
| `--install-firewall-rule` | 添加入站 UDP 防火墙规则后退出（**需管理员**）。server 与 client 是同一个 exe，一条规则两边都覆盖 |
| `--uninstall-firewall-rule` | 删除该规则后退出（需管理员） |
| `--lookup` | `irt diag` 的一个模式：查**对端**在 n0 上公布的地址，而不是体检本机网络 |

### 环境变量

| 变量 | 作用 | 默认 |
|---|---|---|
| `IRT_PUBLISH` | `relay`\|`ip`\|`ipv6`\|`all` | `relay` |
| `IRT_KEY_FILE` | 密钥文件路径 | `%APPDATA%\iroh-rdp-tunnel\server.key` |
| `IRT_RDP` | 被控端 RDP 地址 | `127.0.0.1:3389` |
| `IRT_LISTEN` | 控制端监听地址 | `127.0.0.1:13389` |
| `IRT_RELAY` | 自建 relay URL（逗号分隔） | n0 公共 relay |
| `IRT_ALLOW` | 白名单 endpoint id（逗号分隔） | 不限制 |
| `IRT_CA_FILE` | 额外根证书 PEM 路径 | 无 |
| `IRT_NO_DISCOVERY` | 存在则关闭公共 pkarr / DNS | 关闭 |

优先级：**CLI 参数 > 环境变量 > 默认值**。

### 旧环境变量（兼容保留）

| 变量 | 效果 |
|---|---|
| `NO_RELAY` | 等价于 `--no-relay` |
| `FORCE_RELAY` | 等价于 `--publish all` |
| `FORCE_IPV6` | 等价于 `--publish ipv6` |

---

## 零依赖第三方的三种方案

默认使用 n0 的公共 relay 做**初始会合**。中继只转发**已加密**的 UDP 包，看不到 RDP 内容。

| 方案 | 用法 | 限制 |
|---|---|---|
| **同一 LAN** | `irt server --no-relay`；client 加 `--listen 192.168.x.x:13389` | 仅限同一局域网 |
| **自建 relay** | `irt server --relay https://your-relay/` 与 `irt client <id> --relay https://your-relay/`（自签证书再加 `--ca-file ca.pem`） | 需要一台公网服务器 |
| **Tor 网络** | 改用 [iroh-tor](https://github.com/n0-computer/iroh-tor)，传输层走 Tor | 延迟较高 |

---

## 项目结构

```
.
├── Cargo.toml
├── README.md
├── DESIGN.md                        # 设计文档
├── docs/superpowers/plans/          # 实施计划
├── src
│   ├── lib.rs                       # 模块聚合 + 公共常量
│   ├── cli.rs                       # clap 子命令 + 配置解析
│   ├── config.rs                    # 强类型配置 + 注入式 EnvSource
│   ├── addrpolicy.rs                # 发布策略 → AddrFilter
│   ├── endpoint.rs                  # iroh 端点组装（server/client 共用）
│   ├── keys.rs                      # endpoint 私钥持久化
│   ├── tunnel.rs                    # TCP ↔ QUIC 双向桥接
│   ├── connmgr.rs                   # client 侧常驻连接 + 断线重连
│   ├── pathinfo.rs                  # 直连/中继路径可观测
│   ├── fw.rs                        # Windows 防火墙规则
│   ├── nat.rs                       # NAT 画像与判定
│   ├── portmap.rs                   # UPnP / NAT-PMP / PCP 探测
│   ├── diag.rs                      # 体检报告渲染
│   ├── commands/                    # 三个子命令的实现
│   │   ├── server.rs
│   │   ├── client.rs
│   │   └── diag.rs
│   └── bin
│       └── irt.rs                   # 薄壳入口
└── tests
    └── e2e.rs                       # 端到端测试（进程内 relay，不依赖外网）
```

## 开发

```bash
cargo test          # 单元测试 + 端到端测试
cargo build --release
```

---

## License

MIT OR Apache-2.0
