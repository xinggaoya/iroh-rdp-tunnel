# rustp2p 后端验证结论

> 日期：2026-11-06
> 分支：`feature/v0.3-rustp2p`
> 结论：**rustp2p 后端可用**，但它的可用性边界与 iroh 完全不同 —— 必须写清楚。

---

## 1. 一句话结论

**两个后端各有各的适用场景，缺一不可：**

| | iroh 后端 | rustp2p 后端 |
|---|---|---|
| **一定能连上吗** | ✅ 一定能（走中继） | ❌ **不一定** —— 打洞成功前连不上 |
| **能直连吗** | ❌ 永远不能（对称 NAT 下结构性无解） | ✅ 能（本机实测成功） |
| 延迟 | 高（实测 1200ms，且中继间转发会翻倍） | 低（实测 205ms） |
| 适合 | **保底**：先保证 RDP 能用 | **争取直连**：延迟敏感时用 |

**⇒ 默认仍是 `--transport iroh`（保底可用）**；需要低延迟时切 `--transport rustp2p`。

---

## 2. 关键机制：rustp2p 的「中继兜底」与 iroh 不是一回事

这是本次验证最重要的发现，**必须写进文档，否则会误导用户**。

- **iroh 的中继兜底是真的**：QUIC over relay —— 中继终结不了 TLS，但能转发整条 QUIC 连接。
  ⇒ 打洞失败时 RDP 照样能用，只是慢。
- **rustp2p 的中继是协议层转发**：它的 `QuicRelay` 协议包携带**不透明的 QUIC 密文**
  （源码注释原文：*"The relay payload is opaque QUIC ciphertext"*），
  由协议层转发/注入 quinn。
  ⇒ **QUIC 流的建立仍然需要一条「已确认的路由」**，
  而路由确认要么靠直连打洞成功，要么靠中继路由协商（`IDRouteQuery`/`IDRouteReply`）成功。

**实测**：rustp2p 原生客户端（`spike`，不经过我们的代码）同样卡在 `open_bi` ——
**这不是我们适配层的问题，是 rustp2p 的固有行为**。

⇒ **rustp2p 后端在打洞成功前不可用**。这一点与设计文档 M6
（「打洞预算 5 分钟内、「仍走中继」可接受」）**只对 iroh 后端成立**。

---

## 3. 实测数据

### 3.1 环境

| | |
|---|---|
| 客户端 | 本机 Windows，家宽，公网 IP `220.200.126.10` |
| NAT 类型 | **对称 NAT**（映射随目标变化） |
| 端口分配范围 | 30 000 ~ 62 000 个端口（每次观测都不同） |
| 服务端 | VPS `107.172.191.12`（公网，Docker 里的 `irt server`） |
| 中继 / bootstrap | 同一台 VPS 上的 `rustp2p-node`（Docker，host 网络，6888/udp） |

**交叉验证**：iroh 自己也报告了 `IPv4 address detected by QAD varies by destination`
—— 与 rustp2p 观测到的 `Symmetric` 一致。

### 3.2 同一台机器、同一网络，两个后端的对比

```
iroh    ：[路径·client] ⚠ 30 秒内未建立**公网**直连路径，当前走中继
rustp2p ：[路径·client] ✅ 已切换到直连  107.172.191.12:2525  RTT 200ms
```

**这就是 v0.3 存在的全部理由** —— 同一台机器，iroh 30 秒打不通，rustp2p 9 秒打通。

### 3.3 跨公网完整 RDP 隧道（最终验收）

```
第 1~6 次尝试：超时（约 4 分钟）
第 7 次尝试：收到 262144 字节；完全一致: True
 [路径·client] 中继  107.172.191.12:6888
 [路径·client] ✅ 已切换到直连  107.172.191.12:45434
```

- 数据**逐字节一致** ✓
- 打洞耗时约 **4 分钟** —— 与设计文档 M6 的「5 分钟预算」吻合 ✓
- 中继路径先建立，打洞成功后**自动切到直连** ✓

### 3.4 本地自动化测试

`tests/rustp2p_e2e.rs` —— 进程内三节点（bootstrap 兼中继 / server / client）：

| 测试 | 覆盖 | 结果 |
|---|---|---|
| `rustp2p_tunnel_roundtrips_bytes` | 字节完整性（32 KB） | ✅ |
| `rustp2p_tunnel_roundtrips_large_payload` | 大流量（1 MB） | ✅ |
| `rustp2p_slow_reader_exercises_backpressure` | **背压路径**（2 MB + 对端慢读） | ✅ |
| `rustp2p_half_close_propagates_eof` | 半关闭（EOF 传播） | ✅ |
| `rustp2p_reports_direct_path_on_loopback` | 路径状态判定 | ✅ |

---

## 4. 这次验证揪出并修掉的 4 个真 bug

全部是**适配层**的问题（rustp2p-quic 本身没 bug）：

### 4.1 `poll_write` 违反 `AsyncWrite` 契约 ⇒ 数据重复

`send().await` 的 future 一旦被 poll，数据可能已进队列；此时若返回 `Pending`，
上层（tokio 的 `copy`）以为「什么都没写」，会带着一份**更长的 buf** 重试
（`copy` 在 `poll_write` 挂起期间会继续 `poll_read` 往 buf 里追加）⇒ 旧数据被重复发送。

实测：64 KB 发出，对端收到 **98304** 字节。

**修法**：`try_send` + 本地待发缓冲 `pending_data` ——
`try_send` 失败 ⇒ 数据**一定**没被接受 ⇒ 返回 `Pending` 是诚实的。

### 4.2 背压路径没记账 ⇒ 数据重复（修完 4.1 后暴露）

`pending_data` 送出后没有记账、还继续发新数据 ⇒ 旧数据再发一遍。
必须送出后**立即返回 `Ok(pending_data.len())`**。

实测：2 MB 发出，对端收到 **2116374** 字节。

### 4.3 `open_bi` 无限等待 ⇒ 重试逻辑形同虚设

rustp2p 的 `open_bi` 在路由未建立时**一直等**（不是超时返回）。
⇒ 一次调用就永远挂着。

**修法**：单次尝试加 30 秒超时 + 重试（重试会重新触发一次路由查找，
中继路由确认有时序要求，重试一次就可能赶上），总预算 5 分钟。

### 4.4 「等对端被发现」缺失 ⇒ 挂在路由查找上

对端还没被 bootstrap 的 peer 列表发现时，路由根本不存在，
`open_bi` 会一直挂着、既不报错也不推进。

**修法**：先等对端出现在 `known_peers()` 里（30 秒超时，报错信息说清楚查什么）。

---

## 5. 部署侧踩的坑

| 现象 | 根因 | 处理 |
|---|---|---|
| 客户端 `bootstrap hello timed out` | 端口不在 1Panel 白名单，被 `1PANEL_BASIC_AFTER` 静默 DROP | 换到已放行的 6888 |
| `AddrInUse` | 端口的 **TCP** 被 1Panel 占用（node 同时绑 TCP+UDP） | 换端口 |
| 打洞永远打不通 | **被控端用了 `127.0.0.1` 作 bootstrap** ⇒ 中继观测到的是回环地址 | **两端都必须用公网 bootstrap 地址** |

### 第 3 条尤其值得记

VPS 上的被控端如果写 `--bootstrap 127.0.0.1:6888`（因为中继就在本机），
中继观测到的它的公网端点会是 `127.0.0.1:39477` ⇒
客户端永远打不到 ⇒ QUIC 只能用 synthetic 地址 ⇒ `QUIC handshake timed out`。

**⇒ 被控端与控制端必须用同一个「公网可达」的 bootstrap 地址。**

---

## 7. 跨公网实测：打洞「永远打不通」的根因（2026-11-06 追加）

上面第 6 节说「打洞要 4 分钟」。后续排查发现**不是慢，是打不通**，
而且**根因不在 rustp2p 的算法，在「打洞对象」选错了**。

### 7.1 现象

- 客户端日志反复出现 `QUIC handshake timed out`（每 21 秒一轮，5 分钟预算耗尽）
- 服务端日志**从未**出现 `Failed to accept connection` ⇒ 客户端的 Initial 根本没到服务端
- 有一次打洞成功（`punch succeeded`）之后，**后续握手仍然全部超时**

### 7.2 证据链

1. 客户端 `RUST_LOG=debug` 打出打洞对象：

   ```
   execute_punch -> irt-1c12ce0f...   ← f7 那次的旧客户端（进程早已退出）
   execute_punch -> irt-ede3fa32...   ← 又一个旧实例
   execute_punch -> vps-peer          ← 真正要连的那个
   ```

   ⇒ 客户端在**同时给 9 个 peer 打洞**。

2. 服务端同样：给 8 个旧客户端 + 真正的客户端一起打。

3. 端口空间量化：对称 NAT 实测 3 万~6 万端口；rustp2p 的 Phase 2
   每轮扫 1200~1500 个端口 ⇒ 覆盖全空间需要 **40~50 轮**；
   而 `auto-punching` 循环**每轮只处理一个 peer**、每 peer 10 秒一轮
   ⇒ 目标 peer 的实际频率被稀释到 **1/9** ⇒ **永远打不通**。

4. 双方打的对象**不一致**（一端打 vps-peer，另一端打旧实例）⇒ 永远碰不上。

### 7.3 根因（源码级）

- `rustp2p-quic` 的 `punch_whitelist` 默认为 `None` ⇒ 对**所有**已知 peer 打洞。
- `protocol.rs::try_execute_punch`（**被动**响应对方 `PunchRequest`）
  **不检查** `punch_allowed`，而 `handle_punch_consult_request` 检查 ⇒
  上游白名单语义不一致 ⇒ 被动打洞无法用白名单阻止。
- `PeerInfo::last_seen` **不能**用来判断「peer 还活着」：
  `ingest_route_entries` → `confirm_peer_route` → `upsert_peer_info`
  会把 `last_seen` 刷成本地当前时间（bootstrap 转发 peer 列表时触发）。

### 7.4 修复

| 位置 | 改动 |
|---|---|
| 客户端 | `punch_whitelist = [目标 peer]` —— 只打真正要对话的那一个 |
| 服务端 | `punch_whitelist = --allow-peer` 列表 —— 两端打同一个对象 |
| 部署 | 两端都用**固定 peer id**（`--node-id`），重启不变 |

### 7.5 修复后实测（同一台客户端、同一台 VPS）

```
13:23:32 punch succeeded: direct route confirmed to vps-peer
         via RouteKey { local_addr: 0.0.0.0:50614, peer_addr: 107.172.191.12:48948 }
 [路径·client] ✅ 已切换到直连  107.172.191.12:48948  RTT 215ms

收到 524288 字节；完全一致: True；耗时 7.5s
```

- 打洞耗时：600 秒打不通 → **30 秒打通**
- 512 KB 隧道数据**逐字节一致**
- 路径：**直连**（215ms），不是中继

### 7.6 结论

> 对称 NAT 下打不通，**九成是「打的对象不对/太多」**，不是算法问题。
> 先把打洞对象收敛到「双方要对话的那一对 peer」，再看耗时。

---

## 11. 最终根因：「打洞永远打不通」的**两个**真凶（2026-11-06 收官）

§7 定位的是「打洞对象不对/太多」。修掉之后，同机无 NAT、端口固定、
直连双向确认的干净环境里，**QUIC 握手仍然 100% 超时** ——
说明还有一个更隐蔽、也更致命的问题。

### 11.1 真凶之一：服务端的打洞白名单会**直接废掉对端的直连**

rustp2p-quic 的 `PunchRequest` 处理分支（`protocol.rs`）：

```rust
if self.punch_allowed(&payload.src) {
    self.try_execute_punch(...).await;
    // ★ 只有命中白名单，才回 PunchReply
    self.send_protocol_to_route(src, route_key, ProtocolType::PunchReply, &reply).await?;
} else {
    log::debug!("PunchRequest from {src} ignored (not in whitelist)");
}
```

而**对端正是靠这个 `PunchReply` 来确认自己的直连路由**
（`PunchReply` 分支里 `metric == 0` ⇒ `confirm_direct_and_promote`）。

⇒ **只要对端不在白名单里，服务端就既不打洞、也不回 `PunchReply`
⇒ 对端永远建不起直连 ⇒ QUIC 握手 100% 超时。**

问题在于：最初把服务端的 `--allow-peer` 直接塞进了 `punch_whitelist`，
而**客户端的 peer id 默认是随机生成的**（除非 `--node-id` 固定），
服务端根本无从预先知道 ⇒ 白名单几乎必然匹配不上。

**A/B 实测**（同一台 VPS，两端都在本机，最小变量）：

| 被控端 `punch_whitelist` | 控制端 peer id | 结果 |
|---|---|---|
| `Some([clientZ])` | `clientZ` | ✅ 0.1 秒打通，64KB 逐字节一致 |
| `Some([clientZ])` | `clientZ2` | ❌ 握手超时 |
| `None` | `clientZ2` | ✅ **0.1 秒打通**，64KB 逐字节一致 |

⇒ **修复**：服务端 `punch_whitelist` **恒为 `None`**；
打洞收敛由**客户端**负责（客户端知道服务端的 peer id ⇒ 自动只打它）。
`--allow-peer` 只保留「接入白名单」语义，并在文档里写明
「对端必须用 `--node-id` 固定 peer id 才能匹配」。

### 11.2 真凶之二：`open_bi_via` 让**去程与回程走了不同的路**

`open_bi_via` 会把客户端的 QUIC 连接**钉死**在指定的那条 `route_key` 上
（独立命名空间 `via_virtual_addrs`）。但**服务端不知道这件事** ——
它回包时走的是「路由表查询」（`route_metric_for`），
选的是**另一条**路由。

⇒ **去程与回程路径不对称** ⇒ QUIC 握手包对不上 ⇒ 握手超时。
⇒ 而协议包不走 QUIC，所以**协议层一切正常**、直连也确认成功 ——
**只有 QUIC 层失败**，极具迷惑性。

**⇒ 修复**：客户端改回 `open_bi`（双方都走路由表 ⇒ 路径对称）。

### 11.3 修复后的跨公网实测（真实对称 NAT）

环境：控制端 = 本机（公网 `220.200.126.10`，**对称 NAT**，端口范围 3 万~6 万）、
被控端 = VPS `107.172.191.12`（无 NAT，固定 `--bind 0.0.0.0:45434`）、
bootstrap/中继 = 同 VPS 的 rustp2p node（`6888/udp`）。

```
[客户端] punch succeeded: direct route confirmed to vps-peer
         via RouteKey { local_addr: 0.0.0.0:55645, peer_addr: 107.172.191.12:45434 }
[服务端] punch succeeded: direct route confirmed to test-client
         via RouteKey { local_addr: 0.0.0.0:45434, peer_addr: 220.200.126.10:26209 }
[路径·client] ✅ 已切换到直连  107.172.191.12:45434
```

| 阶段 | 结果 |
|---|---|
| 打洞耗时 | **约 3 秒**（16:42:12 开始 → 16:42:15 确认） |
| 中继路径 512KB | 逐字节一致，6.3 秒 |
| 直连路径 1MB | **逐字节一致，6.4 秒** |

⇒ **rustp2p 后端在真实跨公网对称 NAT 下完全可用。**

### 11.4 附带的可观测性缺口（已补）

rustp2p 不把对端的 `nat_info` / 已确认路由暴露给应用层 ⇒ 新增
`Rustp2pTransport::describe_peer()` 与 `describe_routes()`，
在 `open_stream` 时打印。定位本次问题时，这两个函数直接给出了
「对端端口已过期」「只有中继路由」等关键线索。

---

## 12. 仍需真机验证（用户参与）

本次的客户端是**开发机**（端口范围 3 万~6 万）。
用户的真实场景：

- 被控端：家里（`171.37.192.67`，联通光猫）
- 控制端：公司网（**对称 NAT**，有全局 IPv6）

**需要确认**：

1. 控制端（对称 NAT 那台）打洞是否成功、耗时多久
   —— 若超过 5 分钟预算，应先切回 `--transport iroh` 保底
2. `irt diag --transport rustp2p` 在那台机器上的 NAT 画像与端口范围
3. **有全局 IPv6 的一端是否应该优先走 IPv6 直连**（完全绕开 NAT 遍历）
4. 被控端是否已按 §11.1 去掉 `--allow-peer`（或对端已用 `--node-id` 固定 id）

---

## 13. 建议的默认策略

```
默认 --transport iroh        ← 保底：一定能连上（RDP 可用，延迟高）
需要低延迟时 --transport rustp2p   ← 争取直连（打洞失败则要等/超时）
```

**建议在 rustp2p 后端里加一条提示**：打洞未成功时，提示用户
「可先用 --transport iroh 保底」。

---

## 14. 相关文档

- 可行性 spike：`docs/superpowers/spike/rustp2p-quic-spike.md`
- 部署手册：`docs/deploy/rustp2p-node-vps.md`
- 设计文档：`docs/superpowers/specs/2026-11-06-iroh-rdp-tunnel-v0.3-design.md`
