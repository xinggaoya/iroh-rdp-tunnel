//! 命令行界面：顶层 `irt` + `server` / `client` / `diag` 三个子命令。
//!
//! 配置优先级：**CLI 参数 > 环境变量 > 默认值**。
//! 环境变量通过注入式的 [`EnvSource`] 读取，单元测试不碰进程环境。

use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Args as ClapArgs, Parser, Subcommand};
use iroh::{EndpointId, RelayMode, RelayUrl};

use crate::{
    addrpolicy::PublishPolicy,
    commands,
    config::{
        ClientConfig, EnvSource, Rustp2pSettings, ServerConfig, DEFAULT_ASSISTANT_SOCKETS,
        DEFAULT_STUN_SERVERS,
    },
    endpoint::Discovery,
    transport::TransportKind,
};

/// 顶层命令。
#[derive(Parser, Debug)]
#[command(
    name = "irt",
    version,
    about = "iroh-rdp-tunnel —— Windows RDP 点对点隧道（iroh / rustp2p 双后端）",
    propagate_version = true
)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

/// 子命令。
#[derive(Subcommand, Debug)]
pub enum Command {
    /// 在**被控**的 Windows 机器上运行：监听入站连接并桥接到本机 RDP。
    Server(ServerArgs),
    /// 在**控制端**运行：监听本地端口并桥接到远端。
    Client(ClientArgs),
    /// 网络体检：打印本机 NAT 画像与「是否预期能 P2P 直连」的判定。
    Diag(DiagArgs),
}

/// `irt server` 的参数。
#[derive(ClapArgs, Debug, Clone, Default)]
pub struct ServerArgs {
    /// 对外公布哪些地址：relay | ip | ipv6 | all（默认 relay）。
    #[arg(long, value_name = "POLICY")]
    pub publish: Option<String>,

    /// endpoint 私钥文件路径（默认 %APPDATA%\iroh-rdp-tunnel\server.key）。
    #[arg(long, value_name = "PATH")]
    pub key_file: Option<PathBuf>,

    /// 被控端本机 RDP 地址（默认 127.0.0.1:3389）。
    #[arg(long, value_name = "ADDR")]
    pub rdp: Option<String>,

    /// 自建 relay URL，可重复指定。
    #[arg(long = "relay", value_name = "URL")]
    pub relay: Vec<String>,

    /// 完全禁用 relay（仅同一局域网可用）。
    #[arg(long)]
    pub no_relay: bool,

    /// 允许接入的 endpoint id 白名单，可重复指定（iroh 模式）。
    #[arg(long = "allow", value_name = "ID")]
    pub allow: Vec<String>,

    /// 允许接入的 peer id 白名单，可重复指定（rustp2p 模式）。
    ///
    /// **只是字符串比对，不是身份认证** —— rustp2p 的 peer id 是任意字符串，
    /// 证书校验又被降级为跳过。
    #[arg(long = "allow-peer", value_name = "ID")]
    pub allow_peer: Vec<String>,

    /// 不使用 n0 公共 pkarr / DNS（自建 relay、离线环境）。
    #[arg(long)]
    pub no_discovery: bool,

    /// 额外的根证书文件（PEM），用于信任自签证书的自建 relay。
    #[arg(long, value_name = "PATH")]
    pub ca_file: Option<PathBuf>,

    /// 为本程序添加入站 UDP 防火墙放行规则后退出（需管理员权限）。
    #[arg(long)]
    pub install_firewall_rule: bool,

    /// 删除本程序的入站 UDP 防火墙放行规则后退出（需管理员权限）。
    #[arg(long)]
    pub uninstall_firewall_rule: bool,

    /// 传输后端：iroh | rustp2p（默认 iroh）。
    ///
    /// rustp2p 走自建中继与端口预测打洞，能对付**对称 NAT**；
    /// iroh 的打洞候选只来自中继观测，对称 NAT 下打不通。
    #[arg(long, value_name = "KIND")]
    pub transport: Option<String>,

    /// rustp2p 的本机 peer id（默认随机生成并持久化）。
    #[arg(long, value_name = "ID")]
    pub node_id: Option<String>,

    /// rustp2p 身份文件路径（存 peer id 与证书种子）。
    #[arg(long, value_name = "PATH")]
    pub identity_file: Option<PathBuf>,

    /// rustp2p 的本地监听地址（默认 0.0.0.0:0，由系统分配端口）。
    #[arg(long, value_name = "ADDR")]
    pub bind: Option<String>,

    /// rustp2p 的 bootstrap 节点（公网 VPS 上的 node，兼作中继），可重复指定。
    #[arg(long, value_name = "ADDR")]
    pub bootstrap: Vec<String>,

    /// STUN 服务器，可重复指定（默认三个国内公共 STUN）。
    #[arg(long, value_name = "ADDR")]
    pub stun: Vec<String>,

    /// 对称 NAT 打洞的辅助 socket 数（默认 4）。
    #[arg(long, value_name = "N")]
    pub assistant_sockets: Option<usize>,
}

/// `irt client` 的参数。
#[derive(ClapArgs, Debug, Clone, Default)]
pub struct ClientArgs {
    /// 远端 endpoint id（由 `irt server` 打印）。
    ///
    /// rustp2p 模式下这个位置参数也可以直接写对端的 peer id；
    /// iroh 模式下必须提供。
    #[arg(value_name = "ENDPOINT_ID")]
    pub remote: Option<String>,

    /// 本地「假 RDP」监听地址（默认 127.0.0.1:13389）。
    #[arg(long, value_name = "ADDR")]
    pub listen: Option<String>,

    /// 自建 relay URL，可重复指定。
    #[arg(long = "relay", value_name = "URL")]
    pub relay: Vec<String>,

    /// 完全禁用 relay。
    #[arg(long)]
    pub no_relay: bool,

    /// 不使用 n0 公共 DNS（已知对端地址时使用）。
    #[arg(long)]
    pub no_discovery: bool,

    /// 额外的根证书文件（PEM），用于信任自签证书的自建 relay。
    #[arg(long, value_name = "PATH")]
    pub ca_file: Option<PathBuf>,

    /// 控制端自己的私钥文件路径（默认 %APPDATA%\iroh-rdp-tunnel\client.key）。
    ///
    /// 持久化后控制端的 endpoint id 固定，可以写进被控端的 `--allow` 白名单。
    #[arg(long, value_name = "PATH")]
    pub key_file: Option<PathBuf>,

    /// 为本程序添加入站 UDP 防火墙放行规则后退出（需管理员权限）。
    #[arg(long)]
    pub install_firewall_rule: bool,

    /// 删除本程序的入站 UDP 防火墙放行规则后退出（需管理员权限）。
    #[arg(long)]
    pub uninstall_firewall_rule: bool,

    /// 传输后端：iroh | rustp2p（默认 iroh）。
    #[arg(long, value_name = "KIND")]
    pub transport: Option<String>,

    /// rustp2p 的对端 peer id。
    ///
    /// iroh 模式用位置参数（endpoint id）；rustp2p 模式用这个 ——
    /// 也允许直接用位置参数，两种写法等价。
    #[arg(long, value_name = "ID")]
    pub peer: Option<String>,

    /// rustp2p 的本机 peer id（默认随机生成并持久化）。
    #[arg(long, value_name = "ID")]
    pub node_id: Option<String>,

    /// rustp2p 身份文件路径（存 peer id 与证书种子）。
    #[arg(long, value_name = "PATH")]
    pub identity_file: Option<PathBuf>,

    /// rustp2p 的本地监听地址（默认 0.0.0.0:0，由系统分配端口）。
    #[arg(long, value_name = "ADDR")]
    pub bind: Option<String>,

    /// rustp2p 的 bootstrap 节点（公网 VPS 上的 node，兼作中继），可重复指定。
    #[arg(long, value_name = "ADDR")]
    pub bootstrap: Vec<String>,

    /// STUN 服务器，可重复指定（默认三个国内公共 STUN）。
    #[arg(long, value_name = "ADDR")]
    pub stun: Vec<String>,

    /// 对称 NAT 打洞的辅助 socket 数（默认 4）。
    #[arg(long, value_name = "N")]
    pub assistant_sockets: Option<usize>,
}

/// `irt diag` 的参数。
#[derive(ClapArgs, Debug, Clone, Default)]
pub struct DiagArgs {
    /// 以 JSON 输出，便于脚本处理。
    #[arg(long)]
    pub json: bool,

    /// 改为查询**对端**在 n0 上公布的地址（而不是体检本机网络）。
    ///
    /// 查到的就是客户端实际会拿到的东西：只有 IP 没有 relay 时，
    /// 客户端会被困在直连上，NAT 过滤会让它必然超时。
    #[arg(long, value_name = "ENDPOINT_ID")]
    pub lookup: Option<String>,

    /// 用哪个后端做体检：iroh | rustp2p（默认 iroh）。
    ///
    /// 两个后端的 NAT 观测口径不同，**结论也不同**：
    /// 同一个对称 NAT，iroh 判「直连无望」，rustp2p 判「可破」。
    #[arg(long, value_name = "KIND")]
    pub transport: Option<String>,

    /// rustp2p 体检用的 STUN 服务器，可重复指定（默认三个国内公共 STUN）。
    #[arg(long, value_name = "ADDR")]
    pub stun: Vec<String>,

    /// rustp2p 体检时的辅助 socket 数（默认 4）。
    #[arg(long, value_name = "N")]
    pub assistant_sockets: Option<usize>,
}

/// 解析 `irt server` 的配置。
pub fn resolve_server(args: &ServerArgs, env: &EnvSource) -> anyhow::Result<ServerConfig> {
    let publish = resolve_publish(args, env)?;
    let key_file = match (&args.key_file, env.get("IRT_KEY_FILE")) {
        (Some(p), _) => p.clone(),
        (None, Some(v)) => PathBuf::from(v),
        (None, None) => crate::config::default_key_file(),
    };
    let rdp_target = match (&args.rdp, env.get("IRT_RDP")) {
        (Some(v), _) => v.clone(),
        (None, Some(v)) => v.to_string(),
        (None, None) => crate::config::default_rdp_target().to_string(),
    };
    let rdp_target = rdp_target
        .parse()
        .with_context(|| format!("无法解析 RDP 地址 `{rdp_target}`"))?;

    let relay_mode = resolve_relay_mode(args.no_relay, &args.relay, env)?;
    let discovery = resolve_discovery(args.no_discovery, env);
    let ca_tls_config = resolve_ca(args.ca_file.as_deref(), env)?;
    let transport = resolve_transport(args.transport.as_deref(), env)?;
    let (allow_list, allow_peers) = resolve_allow_list(args, env, transport)?;
    let rustp2p = resolve_rustp2p(
        args.node_id.as_deref(),
        args.identity_file.as_deref(),
        args.bind.as_deref(),
        &args.bootstrap,
        &args.stun,
        args.assistant_sockets,
        env,
        false,
    )?;

    Ok(ServerConfig {
        key_file,
        rdp_target,
        publish,
        relay_mode,
        allow_list,
        allow_peers,
        discovery,
        ca_tls_config,
        transport,
        rustp2p,
    })
}

/// 解析 `irt client` 的配置。
pub fn resolve_client(args: &ClientArgs, env: &EnvSource) -> anyhow::Result<ClientConfig> {
    let transport = resolve_transport(args.transport.as_deref(), env)?;

    // iroh 模式必须有远端 endpoint id；rustp2p 模式用 peer id。
    let raw_remote = args.remote.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let remote = match transport {
        TransportKind::Iroh => {
            let raw = raw_remote.with_context(|| {
                "缺少远端 endpoint id —— 用法: irt client <ENDPOINT_ID>（由 irt server 打印）"
            })?;
            Some(parse_endpoint_id(raw)?)
        }
        TransportKind::Rustp2p => None,
    };
    let peer = resolve_peer(args.peer.as_deref(), raw_remote, transport, env)?;

    let listen = match (&args.listen, env.get("IRT_LISTEN")) {
        (Some(v), _) => v.clone(),
        (None, Some(v)) => v.to_string(),
        (None, None) => crate::config::default_listen().to_string(),
    };
    let listen = listen
        .parse()
        .with_context(|| format!("无法解析监听地址 `{listen}`"))?;
    let relay_mode = resolve_relay_mode(args.no_relay, &args.relay, env)?;
    let discovery = resolve_discovery(args.no_discovery, env);
    let ca_tls_config = resolve_ca(args.ca_file.as_deref(), env)?;
    let key_file = match (&args.key_file, env.get("IRT_CLIENT_KEY_FILE")) {
        (Some(p), _) => p.clone(),
        (None, Some(v)) => PathBuf::from(v),
        (None, None) => crate::config::default_client_key_file(),
    };
    let rustp2p = resolve_rustp2p(
        args.node_id.as_deref(),
        args.identity_file.as_deref(),
        args.bind.as_deref(),
        &args.bootstrap,
        &args.stun,
        args.assistant_sockets,
        env,
        true,
    )?;
    Ok(ClientConfig {
        remote,
        listen,
        relay_mode,
        discovery,
        ca_tls_config,
        key_file,
        transport,
        rustp2p,
        peer,
    })
}

/// 传输后端：CLI `--transport` > 环境变量 `IRT_TRANSPORT` > 默认 `iroh`。
fn resolve_transport(raw: Option<&str>, env: &EnvSource) -> anyhow::Result<TransportKind> {
    if let Some(v) = raw {
        return TransportKind::parse(v);
    }
    if let Some(v) = env.get("IRT_TRANSPORT") {
        return TransportKind::parse(v);
    }
    Ok(TransportKind::Iroh)
}

/// rustp2p 的对端 peer id。
///
/// 优先级：`--peer` > `IRT_PEER` > 位置参数（仅 rustp2p 模式）。
fn resolve_peer(
    cli_peer: Option<&str>,
    positional: Option<&str>,
    transport: TransportKind,
    env: &EnvSource,
) -> anyhow::Result<Option<String>> {
    if let Some(v) = cli_peer {
        let v = v.trim();
        if !v.is_empty() {
            return Ok(Some(v.to_string()));
        }
    }
    if let Some(v) = env.get("IRT_PEER") {
        return Ok(Some(v.trim().to_string()));
    }
    match transport {
        TransportKind::Rustp2p => match positional {
            Some(v) => Ok(Some(v.to_string())),
            None => anyhow::bail!(
                "缺少对端 peer id —— 用法: irt client --transport rustp2p --peer <PEER_ID>，\
                 也可直接写位置参数: irt client <PEER_ID>"
            ),
        },
        TransportKind::Iroh => Ok(None),
    }
}

/// rustp2p 后端的配置。
#[allow(clippy::too_many_arguments)]
fn resolve_rustp2p(
    node_id: Option<&str>,
    identity_file: Option<&Path>,
    bind: Option<&str>,
    bootstrap: &[String],
    stun: &[String],
    assistant_sockets: Option<usize>,
    env: &EnvSource,
    is_client: bool,
) -> anyhow::Result<Rustp2pSettings> {
    let identity_file = match (identity_file, env.get("IRT_IDENTITY_FILE")) {
        (Some(p), _) => p.to_path_buf(),
        (None, Some(v)) => PathBuf::from(v),
        (None, None) => {
            if is_client {
                crate::config::default_client_rustp2p_identity_file()
            } else {
                crate::config::default_rustp2p_identity_file()
            }
        }
    };

    let bind_raw = match (bind, env.get("IRT_BIND")) {
        (Some(v), _) => v.to_string(),
        (None, Some(v)) => v.to_string(),
        (None, None) => "0.0.0.0:0".to_string(),
    };
    let bind = bind_raw
        .parse()
        .with_context(|| format!("无法解析 rustp2p 监听地址 `{bind_raw}`"))?;

    // bootstrap：CLI 优先，CLI 为空时用环境变量。
    let mut bootstrap_list: Vec<String> = bootstrap.to_vec();
    if bootstrap_list.is_empty() {
        bootstrap_list = env.get_list("IRT_BOOTSTRAP");
    }
    let mut bootstrap_addrs = Vec::with_capacity(bootstrap_list.len());
    for s in &bootstrap_list {
        let addr = s
            .trim()
            .parse()
            .with_context(|| format!("无法解析 bootstrap 地址 `{s}`（应为 host:port）"))?;
        bootstrap_addrs.push(addr);
    }

    // STUN：CLI 优先，CLI 为空时用环境变量，再空则用内置默认值。
    let mut stun_list: Vec<String> = stun.to_vec();
    if stun_list.is_empty() {
        stun_list = env.get_list("IRT_STUN");
    }
    if stun_list.is_empty() {
        stun_list = DEFAULT_STUN_SERVERS.iter().map(|s| s.to_string()).collect();
    }

    let max_assistant_sockets = match (assistant_sockets, env.get("IRT_ASSISTANT_SOCKETS")) {
        (Some(v), _) => v,
        (None, Some(v)) => v
            .trim()
            .parse()
            .with_context(|| format!("无法解析辅助 socket 数 `{v}`"))?,
        (None, None) => DEFAULT_ASSISTANT_SOCKETS,
    };

    Ok(Rustp2pSettings {
        node_id: node_id.unwrap_or_default().to_string(),
        identity_file,
        bind,
        bootstrap: bootstrap_addrs,
        stun_servers: stun_list,
        max_assistant_sockets,
    })
}

/// 发布策略：CLI > `IRT_PUBLISH` > 遗留 `FORCE_RELAY` / `FORCE_IPV6` > 默认 `relay`。
fn resolve_publish(args: &ServerArgs, env: &EnvSource) -> anyhow::Result<PublishPolicy> {
    if let Some(v) = &args.publish {
        return PublishPolicy::parse(v);
    }
    if let Some(v) = env.get("IRT_PUBLISH") {
        return PublishPolicy::parse(v);
    }
    if env.get("FORCE_IPV6").is_some() {
        return Ok(PublishPolicy::IpV6Only);
    }
    if env.get("FORCE_RELAY").is_some() {
        return Ok(PublishPolicy::All);
    }
    Ok(PublishPolicy::RelayOnly)
}

/// 中继模式：`--no-relay` / `NO_RELAY` > `--relay` / `IRT_RELAY` > n0 默认。
fn resolve_relay_mode(
    no_relay: bool,
    relay_urls: &[String],
    env: &EnvSource,
) -> anyhow::Result<RelayMode> {
    let env_relays = env.get_list("IRT_RELAY");
    let mut urls: Vec<String> = relay_urls.to_vec();
    urls.extend(env_relays);

    if no_relay || env.get("NO_RELAY").is_some() {
        if !urls.is_empty() {
            anyhow::bail!("不能同时禁用 relay 与指定 --relay");
        }
        return Ok(RelayMode::Disabled);
    }
    if urls.is_empty() {
        return Ok(RelayMode::Default);
    }
    let parsed: Vec<RelayUrl> = urls
        .iter()
        .map(|u| {
            u.parse::<RelayUrl>()
                .with_context(|| format!("不是合法的 relay URL `{u}`"))
        })
        .collect::<anyhow::Result<_>>()?;
    Ok(RelayMode::custom(parsed))
}

/// 白名单：CLI `--allow` > `IRT_ALLOW`。
fn resolve_allow_list(
    args: &ServerArgs,
    env: &EnvSource,
    transport: TransportKind,
) -> anyhow::Result<(Vec<EndpointId>, Vec<String>)> {
    match transport {
        TransportKind::Iroh => {
            let mut raw: Vec<String> = args.allow.clone();
            raw.extend(env.get_list("IRT_ALLOW"));
            let list = raw.iter().map(|s| parse_endpoint_id(s)).collect::<Result<Vec<_>, _>>()?;
            Ok((list, Vec::new()))
        }
        TransportKind::Rustp2p => {
            // rustp2p 的 peer id 是任意字符串 —— **不能**按 endpoint id 解析。
            let mut raw: Vec<String> = args.allow_peer.clone();
            raw.extend(env.get_list("IRT_ALLOW_PEERS"));
            Ok((Vec::new(), raw))
        }
    }
}

/// 解析 endpoint id。
///
/// iroh 的十六进制解码器只认**小写**（HEXLOWER），但用户从各种渠道复制来的
/// id 很可能带大写字母或首尾空白 —— 这里统一归一化。
pub fn parse_endpoint_id(s: &str) -> anyhow::Result<EndpointId> {
    let t = s.trim().to_ascii_lowercase();
    t.parse()
        .with_context(|| format!("不是合法的 endpoint id `{}`", s.trim()))
}

/// 地址发现：CLI `--no-discovery` / `IRT_NO_DISCOVERY` > 公共 pkarr + DNS。
fn resolve_discovery(no_discovery: bool, env: &EnvSource) -> Discovery {
    if no_discovery || env.get("IRT_NO_DISCOVERY").is_some() {
        Discovery::Disabled
    } else {
        Discovery::Public
    }
}

/// 自定义 CA：CLI `--ca-file` > 环境变量 `IRT_CA_FILE` > 无（用系统根证书）。
fn resolve_ca(
    ca_file: Option<&std::path::Path>,
    env: &EnvSource,
) -> anyhow::Result<Option<iroh::tls::CaTlsConfig>> {
    let path = match ca_file {
        Some(p) => Some(p.to_path_buf()),
        None => env.get("IRT_CA_FILE").map(std::path::PathBuf::from),
    };
    match path {
        Some(p) => Ok(Some(crate::endpoint::load_ca_file(&p)?)),
        None => Ok(None),
    }
}

/// 初始化日志。
fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}

/// 入口。
pub async fn run() -> anyhow::Result<()> {
    init_tracing();
    let args = Args::parse();
    let env = EnvSource::from_process();
    match &args.command {
        Command::Server(a) => {
            // 防火墙开关先处理：它与连接配置无关，
            // 不该因为别的参数写错而装不上规则。
            if handle_firewall(a.install_firewall_rule, a.uninstall_firewall_rule)? {
                return Ok(());
            }
            let cfg = resolve_server(a, &env)?;
            commands::server::run(cfg).await
        }
        Command::Client(a) => {
            if handle_firewall(a.install_firewall_rule, a.uninstall_firewall_rule)? {
                return Ok(());
            }
            let cfg = resolve_client(a, &env)?;
            commands::client::run(cfg).await
        }
        Command::Diag(a) => commands::diag::run(a.clone()).await,
    }
}

/// 处理防火墙规则的安装 / 卸载。
///
/// 返回 `true` 表示已经处理完，调用方应当直接退出。
///
/// server 与 client 是同一个可执行文件，打洞时两端都要能收到入站 UDP，
/// 所以两个子命令都支持这两个开关。
pub fn handle_firewall(install: bool, uninstall: bool) -> anyhow::Result<bool> {
    if install && uninstall {
        anyhow::bail!("--install-firewall-rule 与 --uninstall-firewall-rule 不能同时使用");
    }
    if install {
        let exe = crate::fw::current_exe()?;
        crate::fw::install_udp_allow_rule(&exe, crate::fw::RULE_NAME)?;
        println!("✅ 已添加入站 UDP 放行规则");
        println!("   规则名: {}", crate::fw::RULE_NAME);
        println!("   程序  : {}", exe.display());
        return Ok(true);
    }
    if uninstall {
        crate::fw::remove_rule(crate::fw::RULE_NAME)?;
        println!("✅ 已删除入站 UDP 放行规则");
        println!("   规则名: {}", crate::fw::RULE_NAME);
        return Ok(true);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> EnvSource {
        EnvSource::from_pairs(pairs)
    }

    /// 一张自签测试证书（PEM）。
    const PEM_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----
";

    #[test]
    fn server_default_publish_policy_is_relay_only() {
        let cfg = resolve_server(&ServerArgs::default(), &env(&[])).unwrap();
        assert_eq!(cfg.publish, PublishPolicy::RelayOnly);
    }

    #[test]
    fn server_cli_publish_overrides_env() {
        let args = ServerArgs {
            publish: Some("ip".into()),
            ..Default::default()
        };
        let cfg = resolve_server(&args, &env(&[("IRT_PUBLISH", "relay")])).unwrap();
        assert_eq!(cfg.publish, PublishPolicy::IpOnly);
    }

    #[test]
    fn server_env_publish_overrides_default() {
        let cfg = resolve_server(&ServerArgs::default(), &env(&[("IRT_PUBLISH", "ip")])).unwrap();
        assert_eq!(cfg.publish, PublishPolicy::IpOnly);
    }

    #[test]
    fn server_legacy_force_relay_maps_to_all() {
        let cfg = resolve_server(&ServerArgs::default(), &env(&[("FORCE_RELAY", "1")])).unwrap();
        assert_eq!(cfg.publish, PublishPolicy::All);
    }

    #[test]
    fn server_legacy_force_ipv6_maps_to_ipv6_only() {
        let cfg = resolve_server(&ServerArgs::default(), &env(&[("FORCE_IPV6", "1")])).unwrap();
        assert_eq!(cfg.publish, PublishPolicy::IpV6Only);
    }

    #[test]
    fn server_invalid_publish_is_rejected() {
        let args = ServerArgs {
            publish: Some("banana".into()),
            ..Default::default()
        };
        let err = resolve_server(&args, &env(&[])).unwrap_err().to_string();
        assert!(err.contains("banana"), "错误信息应包含非法值: {err}");
    }

    #[test]
    fn server_key_file_cli_overrides_env() {
        let args = ServerArgs {
            key_file: Some(PathBuf::from("/tmp/cli.key")),
            ..Default::default()
        };
        let cfg = resolve_server(&args, &env(&[("IRT_KEY_FILE", "/tmp/env.key")])).unwrap();
        assert_eq!(cfg.key_file, PathBuf::from("/tmp/cli.key"));
    }

    #[test]
    fn server_key_file_env_overrides_default() {
        let cfg = resolve_server(&ServerArgs::default(), &env(&[("IRT_KEY_FILE", "/tmp/env.key")])).unwrap();
        assert_eq!(cfg.key_file, PathBuf::from("/tmp/env.key"));
    }

    #[test]
    fn server_rdp_target_defaults_to_loopback_3389() {
        let cfg = resolve_server(&ServerArgs::default(), &env(&[])).unwrap();
        assert_eq!(cfg.rdp_target.to_string(), "127.0.0.1:3389");
    }

    #[test]
    fn server_rdp_target_env_overrides_default() {
        let cfg = resolve_server(&ServerArgs::default(), &env(&[("IRT_RDP", "127.0.0.1:3390")])).unwrap();
        assert_eq!(cfg.rdp_target.to_string(), "127.0.0.1:3390");
    }

    #[test]
    fn server_invalid_rdp_target_is_rejected() {
        let args = ServerArgs {
            rdp: Some("not-an-addr".into()),
            ..Default::default()
        };
        assert!(resolve_server(&args, &env(&[])).is_err());
    }

    #[test]
    fn server_allow_list_comes_from_cli_and_env() {
        let args = ServerArgs {
            allow: vec!["aa".into()],
            ..Default::default()
        };
        // "aa" 不是合法的 endpoint id → 报错并点名
        let err = resolve_server(&args, &env(&[])).unwrap_err().to_string();
        assert!(err.contains("aa"), "错误信息应包含非法 id: {err}");
    }

    #[test]
    fn server_no_relay_env_disables_relay() {
        let cfg = resolve_server(&ServerArgs::default(), &env(&[("NO_RELAY", "1")])).unwrap();
        assert!(matches!(cfg.relay_mode, RelayMode::Disabled));
    }

    #[test]
    fn server_relay_flag_builds_custom_relay_mode() {
        let args = ServerArgs {
            relay: vec!["https://my-relay.example/".into()],
            ..Default::default()
        };
        let cfg = resolve_server(&args, &env(&[])).unwrap();
        assert!(
            matches!(cfg.relay_mode, RelayMode::Custom(_)),
            "应当使用自建 relay，实际: {:?}",
            cfg.relay_mode
        );
    }

    #[test]
    fn server_no_relay_with_relay_is_rejected() {
        let args = ServerArgs {
            no_relay: true,
            relay: vec!["https://my-relay.example/".into()],
            ..Default::default()
        };
        assert!(resolve_server(&args, &env(&[])).is_err());
    }

    #[test]
    fn client_parses_remote_endpoint_id() {
        let id = "86e9c0158a1f097baf3b17ce917501f5e4e3c244cf9cf57f39dcb187e9e09440";
        let args = ClientArgs {
            remote: Some(id.to_string()),
            ..Default::default()
        };
        let cfg = resolve_client(&args, &env(&[])).unwrap();
        assert_eq!(cfg.remote.unwrap().to_string(), id);
    }

    #[test]
    fn client_trims_whitespace_around_endpoint_id() {
        let id = "86e9c0158a1f097baf3b17ce917501f5e4e3c244cf9cf57f39dcb187e9e09440";
        let args = ClientArgs {
            remote: Some(format!("  {id}\n")),
            ..Default::default()
        };
        assert!(resolve_client(&args, &env(&[])).is_ok());
    }

    #[test]
    fn uppercase_endpoint_id_is_accepted() {
        let lower = "86e9c0158a1f097baf3b17ce917501f5e4e3c244cf9cf57f39dcb187e9e09440";
        let upper = lower.to_ascii_uppercase();
        let a = parse_endpoint_id(lower).unwrap();
        let b = parse_endpoint_id(&upper).unwrap();
        assert_eq!(a, b, "大写 id 必须解析成同一个 endpoint");
    }

    #[test]
    fn mixed_case_endpoint_id_is_accepted() {
        let lower = "86e9c0158a1f097baf3b17ce917501f5e4e3c244cf9cf57f39dcb187e9e09440";
        let mixed: String = lower
            .chars()
            .enumerate()
            .map(|(i, c)| if i % 2 == 0 { c.to_ascii_uppercase() } else { c })
            .collect();
        assert_eq!(parse_endpoint_id(lower).unwrap(), parse_endpoint_id(&mixed).unwrap());
    }

    #[test]
    fn client_uppercase_endpoint_id_is_accepted() {
        let id = "86E9C0158A1F097BAF3B17CE917501F5E4E3C244CF9CF57F39DCB187E9E09440";
        let args = ClientArgs {
            remote: Some(id.to_string()),
            ..Default::default()
        };
        let cfg = resolve_client(&args, &env(&[])).unwrap();
        assert_eq!(cfg.remote.unwrap().to_string(), id.to_ascii_lowercase());
    }

    #[test]
    fn allow_list_accepts_uppercase_ids() {
        let id = "86E9C0158A1F097BAF3B17CE917501F5E4E3C244CF9CF57F39DCB187E9E09440";
        let args = ServerArgs {
            allow: vec![id.to_string()],
            ..Default::default()
        };
        let cfg = resolve_server(&args, &env(&[])).unwrap();
        assert_eq!(cfg.allow_list.len(), 1);
        assert_eq!(cfg.allow_list[0].to_string(), id.to_ascii_lowercase());
    }

    #[test]
    fn client_invalid_endpoint_id_is_rejected_and_mentions_it() {
        let args = ClientArgs {
            remote: Some("not-an-id".to_string()),
            ..Default::default()
        };
        let err = resolve_client(&args, &env(&[])).unwrap_err().to_string();
        assert!(err.contains("not-an-id"), "错误信息应包含非法 id: {err}");
    }

    #[test]
    fn client_key_file_defaults_to_a_dedicated_file() {
        let args = ClientArgs {
            remote: Some("86e9c0158a1f097baf3b17ce917501f5e4e3c244cf9cf57f39dcb187e9e09440".to_string()),
            ..Default::default()
        };
        let cfg = resolve_client(&args, &env(&[])).unwrap();
        assert_eq!(
            cfg.key_file.file_name().and_then(|s| s.to_str()),
            Some("client.key")
        );
    }

    #[test]
    fn client_key_file_env_overrides_default() {
        let args = ClientArgs {
            remote: Some("86e9c0158a1f097baf3b17ce917501f5e4e3c244cf9cf57f39dcb187e9e09440".to_string()),
            ..Default::default()
        };
        let cfg = resolve_client(
            &args,
            &env(&[("IRT_CLIENT_KEY_FILE", "/tmp/c.key")]),
        )
        .unwrap();
        assert_eq!(cfg.key_file, PathBuf::from("/tmp/c.key"));
    }

    #[test]
    fn client_listen_defaults_to_loopback_13389() {
        let args = ClientArgs {
            remote: Some("86e9c0158a1f097baf3b17ce917501f5e4e3c244cf9cf57f39dcb187e9e09440".to_string()),
            ..Default::default()
        };
        let cfg = resolve_client(&args, &env(&[])).unwrap();
        assert_eq!(cfg.listen.to_string(), "127.0.0.1:13389");
    }

    #[test]
    fn client_listen_env_overrides_default() {
        let args = ClientArgs {
            remote: Some("86e9c0158a1f097baf3b17ce917501f5e4e3c244cf9cf57f39dcb187e9e09440".to_string()),
            ..Default::default()
        };
        let cfg = resolve_client(&args, &env(&[("IRT_LISTEN", "127.0.0.1:23389")])).unwrap();
        assert_eq!(cfg.listen.to_string(), "127.0.0.1:23389");
    }

    #[test]
    fn install_and_uninstall_firewall_rule_are_mutually_exclusive() {
        let err = handle_firewall(true, true).unwrap_err().to_string();
        assert!(err.contains("不能同时使用"), "实际: {err}");
    }

    #[test]
    fn handle_firewall_is_a_noop_when_no_flag_is_given() {
        assert!(!handle_firewall(false, false).unwrap());
    }

    #[test]
    fn discovery_defaults_to_public() {
        let cfg = resolve_server(&ServerArgs::default(), &env(&[])).unwrap();
        assert_eq!(cfg.discovery, Discovery::Public);
        let args = ClientArgs {
            remote: Some("86e9c0158a1f097baf3b17ce917501f5e4e3c244cf9cf57f39dcb187e9e09440".to_string()),
            ..Default::default()
        };
        let cfg = resolve_client(&args, &env(&[])).unwrap();
        assert_eq!(cfg.discovery, Discovery::Public);
    }

    #[test]
    fn no_discovery_env_disables_public_lookup() {
        let cfg = resolve_server(&ServerArgs::default(), &env(&[("IRT_NO_DISCOVERY", "1")])).unwrap();
        assert_eq!(cfg.discovery, Discovery::Disabled);
    }

    #[test]
    fn ca_file_env_is_loaded() {
        let dir = std::env::temp_dir().join(format!("irt-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pem = dir.join("ca.pem");
        // 一张自签证书（PEM），只用来验证能被解析。
        std::fs::write(&pem, PEM_CERT).unwrap();
        let cfg = resolve_server(
            &ServerArgs::default(),
            &env(&[("IRT_CA_FILE", pem.to_str().unwrap())]),
        )
        .unwrap();
        assert!(cfg.ca_tls_config.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ca_file_missing_is_rejected() {
        let args = ServerArgs {
            ca_file: Some(std::path::PathBuf::from("/definitely/not/here.pem")),
            ..Default::default()
        };
        assert!(resolve_server(&args, &env(&[])).is_err());
    }

    #[test]
    fn no_discovery_cli_overrides_env() {
        let args = ServerArgs {
            no_discovery: true,
            ..Default::default()
        };
        let cfg = resolve_server(&args, &env(&[])).unwrap();
        assert_eq!(cfg.discovery, Discovery::Disabled);
    }

    // ------------------------------------------------------------------
    // 传输后端选择（v0.3）
    // ------------------------------------------------------------------

    #[test]
    fn transport_defaults_to_iroh() {
        let args = ClientArgs {
            remote: Some(
                "86e9c0158a1f097baf3b17ce917501f5e4e3c244cf9cf57f39dcb187e9e09440".to_string(),
            ),
            ..Default::default()
        };
        let cfg = resolve_client(&args, &env(&[])).unwrap();
        assert_eq!(cfg.transport, TransportKind::Iroh);
    }

    #[test]
    fn transport_cli_selects_rustp2p() {
        let args = ClientArgs {
            transport: Some("rustp2p".to_string()),
            peer: Some("peer-c".to_string()),
            ..Default::default()
        };
        let cfg = resolve_client(&args, &env(&[])).unwrap();
        assert_eq!(cfg.transport, TransportKind::Rustp2p);
        assert_eq!(cfg.peer.as_deref(), Some("peer-c"));
    }

    #[test]
    fn transport_cli_overrides_env() {
        let args = ClientArgs {
            transport: Some("rustp2p".to_string()),
            peer: Some("peer-c".to_string()),
            ..Default::default()
        };
        let cfg = resolve_client(&args, &env(&[("IRT_TRANSPORT", "iroh")])).unwrap();
        assert_eq!(
            cfg.transport,
            TransportKind::Rustp2p,
            "CLI 参数必须胜出环境变量"
        );
    }

    #[test]
    fn transport_from_env_when_cli_absent() {
        let args = ClientArgs {
            peer: Some("peer-c".to_string()),
            ..Default::default()
        };
        let cfg = resolve_client(&args, &env(&[("IRT_TRANSPORT", "rustp2p")])).unwrap();
        assert_eq!(cfg.transport, TransportKind::Rustp2p);
    }

    #[test]
    fn unknown_transport_is_rejected() {
        let args = ClientArgs {
            transport: Some("quic".to_string()),
            ..Default::default()
        };
        let err = resolve_client(&args, &env(&[])).unwrap_err();
        assert!(
            err.to_string().contains("未知的传输后端"),
            "错误信息应说清楚: {err}"
        );
    }

    #[test]
    fn rustp2p_requires_peer_id() {
        let args = ClientArgs {
            transport: Some("rustp2p".to_string()),
            ..Default::default()
        };
        let err = resolve_client(&args, &env(&[])).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("peer id"),
            "错误信息应提到 peer id，实际: {msg}"
        );
    }

    #[test]
    fn rustp2p_peer_can_come_from_positional_arg() {
        let args = ClientArgs {
            transport: Some("rustp2p".to_string()),
            remote: Some("peer-from-positional".to_string()),
            ..Default::default()
        };
        let cfg = resolve_client(&args, &env(&[])).unwrap();
        assert_eq!(cfg.peer.as_deref(), Some("peer-from-positional"));
    }

    #[test]
    fn iroh_still_requires_endpoint_id() {
        let args = ClientArgs {
            transport: Some("iroh".to_string()),
            ..Default::default()
        };
        let err = resolve_client(&args, &env(&[])).unwrap_err();
        assert!(
            format!("{err:#}").contains("endpoint id"),
            "iroh 模式仍必须提供 endpoint id"
        );
    }

    #[test]
    fn bootstrap_list_keeps_cli_order() {
        let args = ServerArgs {
            transport: Some("rustp2p".to_string()),
            bootstrap: vec!["10.0.0.1:7001".to_string(), "10.0.0.2:7001".to_string()],
            ..Default::default()
        };
        let cfg = resolve_server(&args, &env(&[])).unwrap();
        let got: Vec<String> = cfg
            .rustp2p
            .bootstrap
            .iter()
            .map(|a| a.to_string())
            .collect();
        assert_eq!(got, vec!["10.0.0.1:7001", "10.0.0.2:7001"]);
    }

    #[test]
    fn bootstrap_from_env_when_cli_absent() {
        let args = ServerArgs {
            transport: Some("rustp2p".to_string()),
            ..Default::default()
        };
        let cfg = resolve_server(
            &args,
            &env(&[("IRT_BOOTSTRAP", "10.0.0.9:7001, 10.0.0.8:7001")]),
        )
        .unwrap();
        assert_eq!(cfg.rustp2p.bootstrap.len(), 2);
        assert_eq!(cfg.rustp2p.bootstrap[0].to_string(), "10.0.0.9:7001");
    }

    #[test]
    fn invalid_bootstrap_address_is_rejected() {
        let args = ServerArgs {
            transport: Some("rustp2p".to_string()),
            bootstrap: vec!["not-an-addr".to_string()],
            ..Default::default()
        };
        assert!(resolve_server(&args, &env(&[])).is_err());
    }

    #[test]
    fn stun_defaults_to_builtin_servers() {
        let args = ServerArgs {
            transport: Some("rustp2p".to_string()),
            ..Default::default()
        };
        let cfg = resolve_server(&args, &env(&[])).unwrap();
        assert_eq!(cfg.rustp2p.stun_servers.len(), 3);
        assert!(cfg.rustp2p.stun_servers[0].contains("stun."));
    }

    #[test]
    fn stun_cli_overrides_default() {
        let args = ServerArgs {
            transport: Some("rustp2p".to_string()),
            stun: vec!["stun.example.org:3478".to_string()],
            ..Default::default()
        };
        let cfg = resolve_server(&args, &env(&[])).unwrap();
        assert_eq!(cfg.rustp2p.stun_servers, vec!["stun.example.org:3478"]);
    }

    #[test]
    fn assistant_sockets_default_and_override() {
        let args = ServerArgs {
            transport: Some("rustp2p".to_string()),
            ..Default::default()
        };
        let cfg = resolve_server(&args, &env(&[])).unwrap();
        assert_eq!(cfg.rustp2p.max_assistant_sockets, 4);

        let args = ServerArgs {
            transport: Some("rustp2p".to_string()),
            assistant_sockets: Some(9),
            ..Default::default()
        };
        let cfg = resolve_server(&args, &env(&[])).unwrap();
        assert_eq!(cfg.rustp2p.max_assistant_sockets, 9);
    }

    #[test]
    fn rustp2p_allow_peer_is_not_parsed_as_endpoint_id() {
        let args = ServerArgs {
            transport: Some("rustp2p".to_string()),
            allow_peer: vec!["peer-c".to_string()],
            ..Default::default()
        };
        let cfg = resolve_server(&args, &env(&[])).unwrap();
        assert_eq!(cfg.allow_peers, vec!["peer-c".to_string()]);
        assert!(cfg.allow_list.is_empty());
    }
}
