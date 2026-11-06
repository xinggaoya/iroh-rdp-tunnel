//! 命令行界面：顶层 `irt` + `server` / `client` / `diag` 三个子命令。
//!
//! 配置优先级：**CLI 参数 > 环境变量 > 默认值**。
//! 环境变量通过注入式的 [`EnvSource`] 读取，单元测试不碰进程环境。

use std::path::PathBuf;

use anyhow::Context;
use clap::{Args as ClapArgs, Parser, Subcommand};
use iroh::{EndpointId, RelayMode, RelayUrl};

use crate::{
    addrpolicy::PublishPolicy,
    commands,
    config::{ClientConfig, EnvSource, ServerConfig},
    endpoint::Discovery,
};

/// 顶层命令。
#[derive(Parser, Debug)]
#[command(
    name = "irt",
    version,
    about = "iroh-rdp-tunnel —— 基于 iroh 的 Windows RDP 点对点隧道",
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

    /// 允许接入的 endpoint id 白名单，可重复指定。
    #[arg(long = "allow", value_name = "ID")]
    pub allow: Vec<String>,

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
}

/// `irt client` 的参数。
#[derive(ClapArgs, Debug, Clone, Default)]
pub struct ClientArgs {
    /// 远端 endpoint id（由 `irt server` 打印）。
    #[arg(value_name = "ENDPOINT_ID")]
    pub remote: String,

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

    /// 为本程序添加入站 UDP 防火墙放行规则后退出（需管理员权限）。
    #[arg(long)]
    pub install_firewall_rule: bool,

    /// 删除本程序的入站 UDP 防火墙放行规则后退出（需管理员权限）。
    #[arg(long)]
    pub uninstall_firewall_rule: bool,
}

/// `irt diag` 的参数。
#[derive(ClapArgs, Debug, Clone, Default)]
pub struct DiagArgs {
    /// 以 JSON 输出，便于脚本处理。
    #[arg(long)]
    pub json: bool,
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
    let allow_list = resolve_allow_list(args, env)?;
    let discovery = resolve_discovery(args.no_discovery, env);
    let ca_tls_config = resolve_ca(args.ca_file.as_deref(), env)?;

    Ok(ServerConfig {
        key_file,
        rdp_target,
        publish,
        relay_mode,
        allow_list,
        discovery,
        ca_tls_config,
    })
}

/// 解析 `irt client` 的配置。
pub fn resolve_client(args: &ClientArgs, env: &EnvSource) -> anyhow::Result<ClientConfig> {
    let remote: EndpointId = args
        .remote
        .trim()
        .parse()
        .with_context(|| format!("不是合法的 endpoint id `{}`", args.remote))?;
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
    Ok(ClientConfig {
        remote,
        listen,
        relay_mode,
        discovery,
        ca_tls_config,
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
fn resolve_allow_list(args: &ServerArgs, env: &EnvSource) -> anyhow::Result<Vec<EndpointId>> {
    let mut raw: Vec<String> = args.allow.clone();
    raw.extend(env.get_list("IRT_ALLOW"));
    raw.iter()
        .map(|s| {
            s.trim()
                .parse::<EndpointId>()
                .with_context(|| format!("不是合法的 endpoint id `{s}`"))
        })
        .collect()
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
            let cfg = resolve_server(a, &env)?;
            if handle_firewall(a.install_firewall_rule, a.uninstall_firewall_rule)? {
                return Ok(());
            }
            commands::server::run(cfg).await
        }
        Command::Client(a) => {
            let cfg = resolve_client(a, &env)?;
            if handle_firewall(a.install_firewall_rule, a.uninstall_firewall_rule)? {
                return Ok(());
            }
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
            remote: id.to_string(),
            ..Default::default()
        };
        let cfg = resolve_client(&args, &env(&[])).unwrap();
        assert_eq!(cfg.remote.to_string(), id);
    }

    #[test]
    fn client_trims_whitespace_around_endpoint_id() {
        let id = "86e9c0158a1f097baf3b17ce917501f5e4e3c244cf9cf57f39dcb187e9e09440";
        let args = ClientArgs {
            remote: format!("  {id}\n"),
            ..Default::default()
        };
        assert!(resolve_client(&args, &env(&[])).is_ok());
    }

    #[test]
    fn client_invalid_endpoint_id_is_rejected_and_mentions_it() {
        let args = ClientArgs {
            remote: "not-an-id".into(),
            ..Default::default()
        };
        let err = resolve_client(&args, &env(&[])).unwrap_err().to_string();
        assert!(err.contains("not-an-id"), "错误信息应包含非法 id: {err}");
    }

    #[test]
    fn client_listen_defaults_to_loopback_13389() {
        let args = ClientArgs {
            remote: "86e9c0158a1f097baf3b17ce917501f5e4e3c244cf9cf57f39dcb187e9e09440".into(),
            ..Default::default()
        };
        let cfg = resolve_client(&args, &env(&[])).unwrap();
        assert_eq!(cfg.listen.to_string(), "127.0.0.1:13389");
    }

    #[test]
    fn client_listen_env_overrides_default() {
        let args = ClientArgs {
            remote: "86e9c0158a1f097baf3b17ce917501f5e4e3c244cf9cf57f39dcb187e9e09440".into(),
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
            remote: "86e9c0158a1f097baf3b17ce917501f5e4e3c244cf9cf57f39dcb187e9e09440".into(),
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
}
