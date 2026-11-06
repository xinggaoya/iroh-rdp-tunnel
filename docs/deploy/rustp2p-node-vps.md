# 在 VPS 上部署 rustp2p 节点（bootstrap + 中继）

> 适用版本：iroh-rdp-tunnel v0.3
> 目标机器：一台有**公网 IPv4**、**UDP 可达**、能跑 Docker 的 VPS

---

## 0. 这个节点是干什么的

```
   你的电脑（家里/公司，NAT 后面）              VPS（公网）
   ┌──────────────────────────┐                ┌──────────────────────┐
   │ irt client                │                │ rustp2p-node         │
   │   ↕ 打洞（端口预测+穷举）  │ ─────────────► │   bootstrap：交换 peer │
   │   ↕ 失败则走中继           │                │   relay：转发密文     │
   └──────────────────────────┘                └──────────────────────┘
```

**为什么不能继续用 n0 的公共中继**：iroh 的打洞候选**只**来自中继观测到的端点。
在**对称 NAT**（映射随目标变化）下，中继看到的端口与对端真实可达端口对不上号，
打洞**永远**打不通 —— 这是架构性限制，不是配置问题。

rustp2p 用「端口预测 + 全局随机扫描」正面解决对称 NAT，但它的中继必须**自己可控**
（要能观测到两端的真实公网端点，才能算端口范围）。

**一个节点同时干两件事**：bootstrap（让两端互相发现）+ relay（打不通时转发）。
**中继不解密端到端 TLS** —— 它只是转发密文的节点。

---

## 1. 前置条件（最容易踩坑的一步）

### 1.1 端口必须在防火墙白名单里

**1Panel 的 `1PANEL_BASIC_AFTER` 链会 DROP 掉所有未放行的 TCP/UDP**：

```
-A 1PANEL_BASIC_AFTER -p tcp -j DROP
-A 1PANEL_BASIC_AFTER -p udp -j DROP
```

不在白名单里的端口**不会报错**，只是静默丢包 —— 客户端表现为
`bootstrap hello timed out`，非常容易误判成程序问题。

**所以选端口时必须同时满足两条**：

1. **已在 1Panel 白名单里**（tcp + udp **都要**放行）
2. **当前没被占用**（包括 TCP —— rustp2p 的 node 同时监听 TCP 和 UDP）

查看当前放行的端口：

```bash
iptables -S 1PANEL_BASIC | grep -E 'dport (你的端口)'
```

查看占用：

```bash
ss -tanup | grep ":你的端口"
```

> **实战记录**：本项目实际用的是 **6888**。
> 8889 曾被选中，但它的 **TCP** 被 `1panel-core` 占用（node 同时绑 TCP+UDP ⇒ `AddrInUse`）；
> 21000 是空闲的，但**不在 1Panel 白名单** ⇒ 被 DROP ⇒ 客户端 `bootstrap hello timed out`。

### 1.2 客户端的 STUN 要可达

端口预测需要知道「对称 NAT 的端口分配范围」，这靠 STUN 观测。
STUN 服务器不可达 ⇒ 拿不到端口范围 ⇒ 只能纯靠穷举，直连要慢很多。

默认用的三个国内公共 STUN：

```
stun.miwifi.com:3478
stun.chat.bilibili.com:3478
stun.hitv.com:3478
```

> **注意**：它们从**境外** VPS 上未必可达。VPS 本身是公网机、不需要 NAT 观测，
> 所以只要求**客户端**那侧能访问 UDP 3478。

---

## 2. 部署

### 2.1 准备二进制

rustp2p-quic 0.1.2 在 crates.io 上有发布，但没有 release 二进制资产，需要自建：

```bash
git clone --depth 1 --branch v0.1.2 https://github.com/rustp2p/rustp2p.git
cd rustp2p/rustp2p
cargo build -p rustp2p-quic --example node --release
cp target/release/examples/node /opt/rustp2p/bin/node
```

**不想在 VPS 上装 Rust 工具链**（省空间）就用容器编译：

```bash
docker run --rm -v "$PWD":/work -w /work rust:1.99-bookworm \
    cargo build -p rustp2p-quic --example node --release
```

编完把 `rust:1.99-bookworm` 镜像和 `target/` 删掉（能省 2.5 GB）。

### 2.2 放好部署文件

本目录下的三个文件：

| 文件 | 作用 |
|---|---|
| `Dockerfile` | 把 `node` 二进制打进一个 `debian:bookworm-slim` 镜像 |
| `entrypoint.sh` | 顶住 stdin —— node example 是**交互式**的，stdin EOF 就退出 |
| `docker-compose.yaml` | 服务定义（端口、seed、restart 策略） |

放到 VPS 上的一个目录，例如 `/opt/rustp2p/deploy/`：

```bash
mkdir -p /opt/rustp2p/deploy
cd /opt/rustp2p/deploy
# 把 node、entrypoint.sh、Dockerfile、docker-compose.yaml 放进来
```

### 2.3 起服务

```bash
cd /opt/rustp2p/deploy
docker compose build
docker compose up -d
docker ps --filter name=irt-rustp2p-node
docker logs irt-rustp2p-node
```

**期望输出**：

```
peer_id=vps-node
addr=0.0.0.0:6888
```

### 2.4 为什么用 host 网络

```yaml
network_mode: host
```

端口映射（`ports:`）会走 `docker-proxy` —— 一个**用户态代理**。
中继要转发 RDP 流量，多这一跳用户态代理会明显影响吞吐。
host 模式下 node 直接监听宿主端口，没有额外开销。

> host 模式的代价：容器与宿主共享网络栈。
> 本容器只跑一个 node，且 6888 是空闲端口，没有冲突风险。

---

## 3. 验证

### 3.1 服务端自检

```bash
ss -ulnp | grep 6888          # UDP 在听
docker logs irt-rustp2p-node  # peer_id=vps-node
```

### 3.2 客户端连得上（关键验证）

在**客户端机器**上：

```bash
irt client --transport rustp2p --peer vps-node \
           --bootstrap <VPS_IP>:6888
```

期望看到：

```
 [路径·client] 直连  <VPS_IP>:6888  RTT 205ms
```

**看到「直连」就说明打洞成功了** —— 这是 v0.3 的核心目标。

如果只看到「中继」，说明打洞没成功（RDP 仍然可用，只是延迟高）。
排查顺序：

1. 客户端 Windows 防火墙是否放行**入站 UDP**（打洞要双向！）
   ```powershell
   irt client --install-firewall-rule     # 管理员权限
   ```
2. 两端是否用了**同一个** `--bootstrap`
3. 客户端能否访问 UDP 3478（STUN）
   ```bash
   irt diag --transport rustp2p
   ```

### 3.3 完整隧道自检

在一台机器上同时起被控端与控制端（本机自环，最快）：

```bash
# 终端 1：假 RDP（回显）
python -c "import socket,threading
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',13389)); s.listen(8)
def h(c):
    try:
        while True:
            d=c.recv(65536)
            if not d: break
            c.sendall(d)
    finally: c.close()
while True:
    c,_=s.accept(); threading.Thread(target=h,args=(c,),daemon=True).start()"

# 终端 2：被控端
irt server --transport rustp2p --node-id local-a \
           --bootstrap <VPS_IP>:6888 --rdp 127.0.0.1:13389

# 终端 3：控制端
irt client --transport rustp2p --peer local-a \
           --bootstrap <VPS_IP>:6888 --listen 127.0.0.1:13390
```

然后连 `127.0.0.1:13390`，数据应原样回显。

---

## 4. 运维

### 常用命令

```bash
docker logs -f irt-rustp2p-node     # 看日志
docker restart irt-rustp2p-node     # 重启
docker compose down                 # 停止（保留镜像）
docker compose up -d                # 启动
```

### seed 必须固定

`docker-compose.yaml` 里的 `--seed vps-node-seed` **不能随便改** ——
它决定 rustp2p 的证书。改了 seed 就等于换了一台机器：
peer id 不变但证书变了，已有对端的信任关系会失效。

### 更新 rustp2p 版本

```bash
cd /opt/rustp2p && git fetch --tags && git checkout v0.1.3
cargo build -p rustp2p-quic --example node --release
cp target/release/examples/node /opt/rustp2p/deploy/node
cd /opt/rustp2p/deploy && docker compose build && docker compose up -d
```

---

## 5. 踩坑备忘

| 现象 | 根因 | 处理 |
|---|---|---|
| 客户端 `bootstrap hello timed out` | 端口不在 1Panel 白名单，被 `1PANEL_BASIC_AFTER` 静默 DROP | 换到已放行的端口 |
| `Error: Os { code: 98, kind: AddrInUse }` | 端口的 **TCP** 被别的服务占用（node 同时绑 TCP+UDP） | 换端口 |
| 容器起来又退出 | node example 是交互式的，stdin EOF 就退出 | 用 `entrypoint.sh` 顶住 stdin |
| 容器日志一片空白 | `println!` 到文件是块缓冲，进程不退出就不 flush | 加 `stdbuf -oL`（本项目用 entrypoint.sh 时不需要，容器 stdout 是行缓冲的） |
| 打洞一直失败 | 对端 Windows 防火墙没放行入站 UDP | 对端执行 `irt client --install-firewall-rule` |
| 直连要好几分钟 | 客户端 STUN 不通 ⇒ 拿不到端口范围 ⇒ 只能穷举 | 检查 UDP 3478 是否可达 |

---

## 6. 与既有服务共存

本项目的部署**不会动** VPS 上已有的任何东西：

- 不改 1Panel、openresty、gitea、redis、postgresql、mysql 等既有容器
- 不改 1Panel 的防火墙规则（只是**选用**已放行的端口）
- 只新增一个容器 `irt-rustp2p-node` 与一个镜像 `rustp2p-node:v0.3`

---

## 7. 相关文档

- 设计文档：`docs/superpowers/specs/2026-11-06-iroh-rdp-tunnel-v0.3-design.md`
- 可行性验证：`docs/superpowers/spike/rustp2p-quic-spike.md`
- 项目 README：`README.md`（含 rustp2p 后端的使用说明）
