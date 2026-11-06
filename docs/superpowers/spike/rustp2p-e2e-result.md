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

## 6. 仍需真机验证（用户参与）

本次的客户端是**开发机**（端口范围 3 万~6 万，打洞要 4 分钟）。
用户的真实场景：

- 被控端：家里（`171.37.192.67`，联通光猫）
- 控制端：公司网（**对称 NAT**，有全局 IPv6）

**需要确认**：

1. 控制端（对称 NAT 那台）打洞是否成功、耗时多久
   —— 若超过 5 分钟预算，应先切回 `--transport iroh` 保底
2. `irt diag --transport rustp2p` 在那台机器上的 NAT 画像与端口范围
3. **有全局 IPv6 的一端是否应该优先走 IPv6 直连**（完全绕开 NAT 遍历）

---

## 7. 建议的默认策略

```
默认 --transport iroh        ← 保底：一定能连上（RDP 可用，延迟高）
需要低延迟时 --transport rustp2p   ← 争取直连（打洞失败则要等/超时）
```

**建议在 rustp2p 后端里加一条提示**：打洞未成功时，提示用户
「可先用 --transport iroh 保底」。

---

## 8. 相关文档

- 可行性 spike：`docs/superpowers/spike/rustp2p-quic-spike.md`
- 部署手册：`docs/deploy/rustp2p-node-vps.md`
- 设计文档：`docs/superpowers/specs/2026-11-06-iroh-rdp-tunnel-v0.3-design.md`
