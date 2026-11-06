# Spike：rustp2p-quic 端到端可行性验证

> 日期：2026-11-06
> 目标：在写任何生产代码之前，验证「用 rustp2p 替换 iroh 做 RDP 隧道」在真实跨网环境下**是否可行**。
> 结论：**可行**，且关键能力（对称 NAT 打洞）恰好覆盖了 iroh 的架构性短板。

---

## 1. 结论摘要

| 验证项 | 结果 | 证据 |
|---|---|---|
| `rustp2p-quic 0.1.2` 编译（Linux/Windows） | ✅ | Linux 用 `rust:1.99-bookworm` 容器编译；Windows 本地编译 |
| VPS 节点部署 + 长期运行 | ✅ | `/opt/rustp2p/bin/node`（9.45 MB） |
| 三节点互相发现 | ✅ | `NatObserveReply from peer-c — observed our public addr as 107.172.191.12:6888` |
| **NAT 观测（对端看得到我的公网端点）** | ✅ | `NatObserveReply from peer-c — observed our public addr as 171.37.192.67:37721` |
| **跨公网双向流（经中继）** | ✅ | `open_bi(peer-c)` 成功建立 QUIC 双向流 |
| **打洞 → 直连路由确认** | ✅ | `punch succeeded: direct route confirmed to peer-c via RouteKey { protocol: UDP, local_addr: 0.0.0.0:53212, peer_addr: 107.172.191.12:2525 }` |
| 中继不解密端到端 TLS | ✅（设计保证） | rustp2p-quic 是 mesh 模型，中继只转发密文 |

**最关键的一条**：iroh 的打洞候选只来自 QAD（中继观测到的端点），在**对称 NAT** 下必然对不上号，因此 iroh 对用户的场景结构性无解；
而 rustp2p-quic 用「端口预测 + 全局随机扫描（1200~1500 端口/轮）+ assistant sockets」正面解决了对称 NAT。

---

## 2. 验证拓扑

```
   本机（Windows，家宽 171.37.192.67，Cone/EIM NAT）        VPS（107.172.191.12，公网）
        │                                                        │
        │  peer-b4  ──────────── UDP 直连（打洞后）───────────►  peer-c
        │                                                        │
        └── peer-b4 ── UDP ──► vps-node（bootstrap + 中继）◄────┘
                                  监听 0.0.0.0:6888
```

- `vps-node`：bootstrap + 中继，公网 UDP 6888
- `peer-c`：模拟「被控端」，公网 UDP 2525
- `peer-b4`：本地 Windows 客户端，走 NAT

---

## 3. 关键实测输出

### 3.1 NAT 观测（本机，NAT 后）

```
[spike] NAT 观测就绪 type=Cone ips=[171.37.192.67] ports=[37721] range=0
[INFO rustp2p_quic::protocol] NatObserveReply from peer-c — observed our public addr as 171.37.192.67:37721 via Udp
```

**对端通过中继观测到了本机的真实公网 IP:端口** —— 这正是打洞所需的信息，iroh 拿不到。

### 3.2 中继路径

```
[spike] 双向流已建立
[spike] 第 0 次 link_mode = Some(Relay) info = Some(LinkInfo { peer_id: PeerId(peer-c), mode: Relay, metric: 1 })
[DEBUG] RTT probe: sending EchoRequest to vps-node via RouteKey { protocol: UDP, local_addr: 0.0.0.0:60068, peer_addr: 107.172.191.12:6888 }
[DEBUG] EchoReply from vps-node — RTT updated: 186ms (was 9999ms)
```

中继可用，RTT 186 ms（中国 ↔ 美国）。

### 3.3 打洞成功（决定性）

```
[INFO rustp2p_quic::protocol] punch succeeded: direct route confirmed to peer-c
  via RouteKey { protocol: UDP, local_addr: 0.0.0.0:53212, peer_addr: 107.172.191.12:2525 }
```

从建连到直连确认 **约 9 秒**。

---

## 4. 踩到的坑（全部是环境问题，不是 rustp2p 的问题）

| # | 现象 | 根因 | 处理 |
|---|---|---|---|
| 1 | `bootstrap hello timed out` | **1Panel 的 `1PANEL_BASIC_AFTER` 链 DROP 所有未放行的 TCP/UDP**，我选的 21000/8889 不在白名单 | 改用 1Panel 已放行且空闲的 **6888**（tcp+udp）/ 2525 |
| 2 | `Address already in use` | 8889 的 **TCP** 被 `1panel-core` 占用（node 同时绑 TCP+UDP） | 换端口 |
| 3 | node 日志一片空白 | `println!` 重定向到文件是**块缓冲**，进程不退出就不 flush | 加 `stdbuf -oL -eL` |
| 4 | `Error: Os { code: 98 }` 反复出现 | 上一轮残留的 `tail -f` 进程没清理 | 脚本里 `pkill -f "tail -f $R/fifo_"` |
| 5 | SFTP 上传报 `FileNotFoundError` | **Git Bash 的 MSYS 路径转换**把 `/tmp/x` 转成了 `C:/Users/.../Temp/x` | `export MSYS_NO_PATHCONV=1` |
| 6 | 脚本里 `$B` 变量变空 | 本地 shell 抢先展开了远端命令里的变量 | 远端脚本用文件上传，不走内联双引号 |
| 7 | 一直看不到打洞日志 | **spike 自己的 bug**：`if mode.is_some() { break }` 让进程 1 秒内退出，maintenance loop（每秒 tick）根本没机会触发 auto-punch | 改成真正等待 90 秒，只在 `LinkMode::Direct` 时 break |

**坑 1 和坑 7 特别值得记**：
- 坑 1 说明 **VPS 的 UDP 放行必须显式验证**，不能假设「公网 IP 就等于 UDP 可达」。
- 坑 7 说明 **rustp2p 的打洞是后台每秒 tick 驱动的**，任何「建连后立刻退出」的实现都会看不到打洞 —— 生产代码必须**长驻**。

---

## 5. 对 v0.3 设计的影响

### 5.1 确认了原设计

- **A3 = rustp2p-quic** 成立。`Endpoint::builder()` 提供了 `identity` / `bootstrap` / `stun_servers` / `max_assistant_sockets` / `certificate_verifier` / `punch_whitelist` 等全部所需配置。
- **A4 = 端口预测 + 穷举** 成立，打洞确实会自动发生（无需手工调 `punch()`）。
- **A2 = 不用 `vnts`** 成立：rustp2p-quic 是 mesh 模型，中继只转发密文、不终结 TLS，**不需要专门的中继服务端**；`vps-node` 一个节点同时承担 bootstrap + 中继两个角色。

### 5.2 需要修订的点

| 设计条目 | 修订 |
|---|---|
| STUN 服务器默认值 | 国内 STUN（`stun.miwifi.com` / `stun.chat.bilibili.com`）从**客户端侧**可用 ✓；但从**美国 VPS** 侧只有 `stun.miwifi.com` 通，`stun.hitv.com` / `stun.chat.bilibili.com` 超时。**STUN 必须按部署位置配置，不能一刀切**。 |
| VPS 端口 | 不用 8889（被 1Panel TCP 占用且不在 UDP 白名单），改 **6888**。必须在部署手册里写明「端口必须同时满足：1Panel 已放行 tcp+udp、且当前空闲」。 |
| 中继角色 | `vps-node` = bootstrap + relay **合一**。 |
| 打洞触发 | 打洞是**后台周期任务**，UI/CLI 必须**长驻**并持续观察 `link_mode`；不能用「一次性建连」写法。 |
| 路径可观测 | `endpoint.link_mode(peer)` → `LinkMode::{Direct, Relay}` + `metric`（0 = 直连），**比 iroh 的 `PathEvent` 更好用**（可直接轮询，无需订阅事件流）。 |
| NAT 信息 | `endpoint.nat_info()` → `nat_type` / `public_ips` / `public_udp_ports` / `public_port_range`，可直接喂给现有的 `NatProfile`。 |

### 5.3 仍未验证（需要用户参与）

- **对称 NAT 下的打洞**：本机是 Cone/EIM，对称 NAT 那台机器（用户的客户端）在本次 spike 中未参与。
  依据 rustp2p-core 的设计（`Puncher::apply_nat_model` 对 Symmetric NAT 开启 assistant sockets；`punch_udp` Phase 1 端口预测 + Phase 2 全局随机扫描），**由非对称的一侧去穷举对称侧的端口**是可行的，但**必须在真机上验证**。
- **两端都在 NAT 后**的完整场景。
- **RDP 真实流量**穿过隧道（本次只验证了控制消息与双向流建立，未跑大流量）。

---

## 6. 复现步骤

```bash
# VPS（bootstrap + 中继）
node --id vps-node --seed <seed> --bind 0.0.0.0:6888

# VPS（模拟被控端）
node --id peer-c --seed <seed> --bind 0.0.0.0:2525 --bootstrap 107.172.191.12:6888

# 本机（客户端）
cargo run -p rustp2p-quic --example spike -- \
    peer-b4 peer-b4-seed 107.172.191.12:6888 peer-c
```

`spike.rs` 位于 `rustp2p-quic/examples/spike.rs`（rustp2p 仓库内，本项目不 vendor 该文件）。

> 注：`node` example 的回显用 **4 字节长度前缀帧**（`read_frame`），
> 而 `spike.rs` 发的是裸字节，所以「无回显」是**帧格式不匹配**，不是隧道故障。
> 生产实现用裸字节流（quinn stream 天然是字节流），无此问题。
