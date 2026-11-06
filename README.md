# iroh-rdp-tunnel

一个最小化的 **P2P RDP 远程桌面隧道**：基于 [iroh](https://github.com/n0-computer/iroh) 在两端建立 QUIC 连接，把控制端的本地 TCP 端口直接桥到被控端的 Windows RDP 服务（3389）。

**实际使用仍然使用系统自带的远程桌面工具**（mstsc / 移动端 RD Client / macOS Microsoft Remote Desktop），不需要安装任何额外的客户端软件。

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
 本地 TCP 监听 : 127.0.0.1:13389

 正在与远端建立连接…

 用系统自带的远程桌面连接本机端口:
     Windows : mstsc /v:127.0.0.1:13389
     Mac     : Microsoft Remote Desktop → 地址填 127.0.0.1:13389
     手机    : RD Client → 地址填 127.0.0.1:13389
 (Ctrl-C 退出)
```

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

---

## 排障决策树

| 现象 | 排查顺序 |
|---|---|
| **client 连不上**（一直转圈） | 1. `irt server` 是不是还开着、id 抄对了吗<br>2. 被控端能上外网吗（`irt diag` 看公网端点）<br>3. 防火墙：被控端跑过 `irt server --install-firewall-rule` 吗 |
| **一直显示「中继」，没有「✅ 已切换到直连」** | 1. 防火墙规则装了吗（**最常见原因**）<br>2. 跑 `irt diag` 看映射行为是不是 EIM<br>3. 中继延迟高（>150ms）？换一个更近的 relay：`irt server --relay https://aps1-1.relay.n0.iroh.link./`<br>4. 对端也在 NAT 后面？**双方都要能打洞** |
| **首帧很慢，之后正常** | 打洞本身要几次往返，第一次连接会慢一些。第二次连接因为连接已建立会很快 |
| **mstsc 报「无法连接到 127.0.0.1:13389」** | client 没运行；或端口被占用；或本机防火墙拦了本地回环 |
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
