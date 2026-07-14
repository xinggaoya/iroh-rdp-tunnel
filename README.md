# iroh-rdp-tunnel

一个最小化的 **P2P RDP 远程桌面隧道**，基于 [iroh](https://github.com/n0-computer/iroh) 在两端建立 QUIC 连接，把控制端的本地 TCP 端口直接桥到被控端的 Windows RDP 服务（3389）。

实际使用**仍然使用系统自带的远程桌面工具**（mstsc / 移动端 RD Client / macOS Microsoft Remote Desktop），不需要安装任何额外的客户端软件。

---

## 它是怎么工作的

```
┌─ 被控 Windows（家里）───────────────┐         ┌─ 控制端（手机/办公电脑）──────┐
│                                    │         │                                │
│  Windows 自带 RDP                   │         │  mstsc.exe / RD Client          │
│       ↑                            │         │       ↑                        │
│  127.0.0.1:3389 ←──────────────────┐│         │  127.0.0.1:13389 ←─────────────┐│
│                                    ││         │       ↑                    ││
│  ┌──────────────────────────┐      ││  iroh   │  ┌──────────────────┐       ││
│  │  irt server  (本次)        │─────┼┼─ QUIC ──┼──│ irt client (本次)  │       ││
│  │  - iroh endpoint         │      ││ P2P     │  │  - iroh endpoint  │       ││
│  │  - 每来一个 stream         │      ││ (打洞+   │  │  - 本地 TCP       │       ││
│  │    → 转发到 127.0.0.1:3389│      ││  中继)   │  │    监听 13389      │       ││
│  └──────────────────────────┘      ││         │  └──────────────────┘       ││
└────────────────────────────────────┘│         └────────────────────────────────┘
```

QUIC 自带 TLS 端到端加密，所以 RDP 的明文数据全程是密文。

---

## 系统要求

### 在被控的 Windows 机器上

1. **Windows 10 / 11 专业版或以上**（家庭版没有 RDP Server，只有客户端）
2. 启用远程桌面：
   - `设置` → `系统` → `远程桌面` → 启用
   - 或运行： `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f`
3. （可选）放行防火墙：`netsh advfirewall firewall add rule name="RDP" dir=in action=allow protocol=TCP localport=3389`
4. 确认本地 RDP 在通：`Test-NetConnection -ComputerName 127.0.0.1 -Port 3389`（PowerShell）应返回 `TcpTestSucceeded: True`

### 在控制端机器上

任意能装 `mstsc` / RD Client 的平台都行。

---

## 编译

### 在 Linux / macOS 上跨编译 Windows 版本（推荐）

```bash
# 安装 Rust（如未安装）
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 编译 Linux 版本（自测用）
cargo build --release
# 产物：target/release/{server,client}

# 跨编译 Windows 版本（拿到 Windows 上跑）
rustup target add x86_64-pc-windows-gnu
apt install -y mingw-w64   # Debian/Ubuntu，其他发行版请自行调整
cargo build --release --target x86_64-pc-windows-gnu
# 产物：target/x86_64-pc-windows-gnu/release/{server.exe,client.exe}
```

### 直接在 Windows 上编译

1. 安装 [Rust](https://rustup.rs/)（选 MSVC 工具链，默认即可）
2. 在项目根目录：
   ```powershell
   cargo build --release
   # 产物：target\release\server.exe, client.exe
   ```

---

## 使用步骤

### 1. 在被控 Windows 上：启动 server

把 `server.exe` 拷过去，双击或在 PowerShell 里：

```powershell
.\server.exe
```

启动后会看到：

```
=========================================================
 iroh-rdp-tunnel SERVER is ready
=========================================================
 Copy this endpoint id into the `client` on the other machine:

     86e9c0158a1f097baf3b17ce917501f5e4e3c244cf9cf57f39dcb187e9e09440

 Waiting for client connection... (Ctrl-C to exit)
```

把那一长串十六进制 endpoint id 复制下来（微信 / 邮件 / 抄在本子上都行）。

> ⚠️ 这个 id 每次启动都会变。如果想固定，把 `SecretKey::generate()` 换成从文件读取，详见 [源码里 server.rs](./src/bin/server.rs) 修改点。

### 2. 在控制端：启动 client

```powershell
.\client.exe 86e9c0158a1f097baf3b17ce917501f5e4e3c244cf9cf57f39dcb187e9e09440
```

客户端输出：

```
=========================================================
 iroh-rdp-tunnel CLIENT is ready
=========================================================
 remote endpoint   = 86e9c0158a…
 local TCP listen  = 127.0.0.1:13389

 Open Windows' Remote Desktop Connection (mstsc) and connect to:
     127.0.0.1:13389
```

### 3. 用 Windows 自带的远程工具连接

**Windows**：
```powershell
mstsc /v:127.0.0.1:13389
```

**Mac**：
打开 "Microsoft Remote Desktop" → 添加 PC → 地址填 `127.0.0.1:13389`

**iOS / Android**：
打开 "RD Client"（微软官方的）→ 添加 → 手动 → 地址 `127.0.0.1:13389`

凭据填被控端 Windows 的**本机账户用户名 + 密码**。

---

## 网络说明

### 默认模式（presets::N0）

- 双方首次连接时会通过 **n0 的公共中继** 协调（`https://euc1-1.relay.n0.iroh.link./` 等）
- 中继服务器只转发**已加密**的 UDP 包，看不到 RDP 内容
- 打洞成功后会**自动切换到直连**，之后就不再走中继
- 端到端加密（TLS），n0 服务器无法解密

> 这意味着「**不依赖你自己拥有的服务器**」—— 但严格说**仍依赖 n0 的中继**做初始打洞握手。如果完全不能接受这一点，见下面三个方案。

### 零依赖第三方的三种方案

| 方案 | 用法 | 限制 |
|---|---|---|
| **同一 LAN** | 加环境变量 `NO_RELAY=1` 启动 server；client 加 `--listen 192.168.x.x:13389`（让 LAN 上的 mstsc 也能连） | 仅限同一局域网 |
| **Tor 网络** | 改用 [iroh-tor](https://github.com/n0-computer/iroh-tor)，传输层走 Tor | 自建 iroh-tor relay（仓库内有）；延迟较高 |
| **自建 relay** | 用本仓库同源的 [`iroh-relay`](https://github.com/n0-computer/iroh/tree/main/iroh-relay)，server 和 client 都加上自定义 `RelayUrl` | 需要一台公网服务器 |

---

## 故障排查

| 现象 | 可能原因 / 处理 |
|---|---|
| `mstsc` 报错 "无法连接到 127.0.0.1:13389" | client 没有运行；或端口被占用；或防火墙拦截本地回环连接 |
| client 一直连接不上，提示超时 | server 没起来、endpoint id 抄错、两端都没法访问外网（无法走 n0 relay） |
| `local RDP not running on 127.0.0.1:3389` | 被控端没有启用 RDP，或服务被禁用 |
| 远程桌面提示账户密码错误 | RDP 要求**被控端的本机账户** + 密码；某些家庭版 / 简化账户请改成 Microsoft 账户 |
| 想要更稳定的 id（每次启动不变） | 修改 `src/bin/server.rs`，把 `SecretKey::generate()` 改成从文件 `read()`；用 `SecretKey::from_bytes(&file_bytes)` |
| 想要更强的访问控制 | 在 `BridgeHandler::accept` 里通过 `conn.remote_id()` 比对白名单，拒绝不在名单里的连接 |

---

## 项目结构

```
.
├── Cargo.toml
├── README.md
└── src
    ├── lib.rs                # 共享常量 (ALPN, RDP_LOCAL)
    └── bin
        ├── server.rs         # 被控端：监听 iroh，把每条 QUIC stream 桥到本地 3389
        └── client.rs         # 控制端：开本地 127.0.0.1:13389，对每个 TCP 连接 open_bi 一条 QUIC stream 到远端
```

---

## License

MIT OR Apache-2.0
