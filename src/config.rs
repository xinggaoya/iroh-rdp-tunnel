//! 配置层：把 CLI 参数与环境变量解析成强类型配置。
//!
//! 设计要点：环境变量通过注入式的 [`EnvSource`] 读取，**不直接读进程环境**，
//! 这样单元测试可以在不污染进程环境的前提下覆盖「CLI > 环境变量 > 默认值」的优先级。

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use iroh::{EndpointId, RelayMode};

use iroh::tls::CaTlsConfig;

use crate::{
    addrpolicy::PublishPolicy, endpoint::Discovery, transport::TransportKind,
};

/// 默认 STUN 服务器（国内可达）。
///
/// STUN 用来观测自己的公网映射端口 —— **对称 NAT 下端口预测必须靠它**，
/// 没有 STUN 观测就拿不到端口范围，打洞只能靠穷举，命中率大幅下降。
///
/// 注意：这些是国内的公共 STUN，从**境外** VPS 上未必可达；
/// VPS 是公网机、不需要 NAT 观测，所以不影响。
pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.miwifi.com:3478",
    "stun.chat.bilibili.com:3478",
    "stun.hitv.com:3478",
];

/// 默认的辅助打洞 socket 数。
///
/// 对称 NAT 下必须开辅助 socket —— 单个 socket 的映射端口空间太小，
/// 端口预测命中率会低到 practically 无用。
pub const DEFAULT_ASSISTANT_SOCKETS: usize = 4;

/// rustp2p 后端的配置。
#[derive(Debug, Clone)]
pub struct Rustp2pSettings {
    /// 本机 peer id（任意字符串）。
    pub node_id: String,
    /// 身份文件路径 —— 存 peer id 与证书种子，**必须持久化**。
    ///
    /// 种子丢了就等于换了一台机器：peer id 不变但证书变了，
    /// 对端会认为身份被冒用。
    pub identity_file: PathBuf,
    /// 本地监听地址。
    pub bind: SocketAddr,
    /// bootstrap 节点地址（公网 VPS 上的 node，兼作中继）。
    pub bootstrap: Vec<SocketAddr>,
    /// STUN 服务器列表。
    pub stun_servers: Vec<String>,
    /// 辅助打洞 socket 数。
    pub max_assistant_sockets: usize,
}

impl Default for Rustp2pSettings {
    fn default() -> Self {
        Self {
            node_id: String::new(),
            identity_file: default_rustp2p_identity_file(),
            bind: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            bootstrap: Vec::new(),
            stun_servers: DEFAULT_STUN_SERVERS.iter().map(|s| s.to_string()).collect(),
            max_assistant_sockets: DEFAULT_ASSISTANT_SOCKETS,
        }
    }
}

/// 被控端配置。
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// endpoint 私钥文件路径。
    pub key_file: PathBuf,
    /// 被控端本机 RDP 服务地址。
    pub rdp_target: SocketAddr,
    /// 对外公布哪些地址。
    pub publish: PublishPolicy,
    /// 中继模式（禁用 / n0 默认 / 自建）。
    pub relay_mode: RelayMode,
    /// 允许接入的 endpoint id 白名单；空表示不限制。
    ///
    /// 只有 iroh 模式用这个。rustp2p 模式见 [`Self::allow_peers`]。
    pub allow_list: Vec<EndpointId>,
    /// 允许接入的 peer id 白名单；空表示不限制。
    ///
    /// **只是字符串比对，不是身份认证** —— rustp2p 的 peer id 是应用层
    /// 任意字符串、证书校验又被降级为跳过。它只挡「手滑连错机器」，
    /// 挡不住有意伪造。见设计文档 §9.4。
    pub allow_peers: Vec<String>,
    /// 是否启用 n0 公共 pkarr / DNS。
    pub discovery: Discovery,
    /// 自定义 CA 信任配置；`None` 表示使用内置/系统根证书。
    pub ca_tls_config: Option<CaTlsConfig>,
    /// 传输后端。
    pub transport: TransportKind,
    /// rustp2p 后端配置（`transport == Rustp2p` 时生效）。
    pub rustp2p: Rustp2pSettings,
}

/// 控制端配置。
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// 远端 endpoint id。
    ///
    /// 只有 iroh 模式才有 —— rustp2p 模式用 [`Self::peer`]。
    pub remote: Option<EndpointId>,
    /// 本地「假 RDP」监听地址。
    pub listen: SocketAddr,
    /// 中继模式。
    pub relay_mode: RelayMode,
    /// 是否启用 n0 公共 DNS 解析。
    pub discovery: Discovery,
    /// 自定义 CA 信任配置；`None` 表示使用内置/系统根证书。
    pub ca_tls_config: Option<CaTlsConfig>,
    /// 控制端自己的私钥文件路径。
    ///
    /// 持久化后控制端的 endpoint id 是固定的，可以直接写进被控端的
    /// `--allow` 白名单里 —— 否则白名单没法用（客户端每次启动都是新 id）。
    pub key_file: PathBuf,
    /// 传输后端。
    pub transport: TransportKind,
    /// rustp2p 后端配置（`transport == Rustp2p` 时生效）。
    pub rustp2p: Rustp2pSettings,
    /// rustp2p 对端的 peer id。
    ///
    /// iroh 模式下用 `remote`（endpoint id）；rustp2p 模式下用这个。
    pub peer: Option<String>,
}

/// 注入式环境变量来源。
#[derive(Debug, Clone, Default)]
pub struct EnvSource {
    vars: BTreeMap<String, String>,
}

impl EnvSource {
    /// 从当前进程环境构造。
    pub fn from_process() -> Self {
        Self {
            vars: std::env::vars().collect(),
        }
    }

    /// 从键值对构造（测试与回放用）。
    pub fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        Self {
            vars: pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    /// 读取一个变量；存在但为空字符串时视为未设置。
    pub fn get(&self, key: &str) -> Option<&str> {
        match self.vars.get(key) {
            Some(v) if !v.trim().is_empty() => Some(v.as_str()),
            _ => None,
        }
    }

    /// 读取一个逗号分隔的变量。
    pub fn get_list(&self, key: &str) -> Vec<String> {
        match self.get(key) {
            None => Vec::new(),
            Some(v) => v
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

/// 密钥文件默认路径。
///
/// - Windows：`%APPDATA%\iroh-rdp-tunnel\server.key`
/// - 其它平台：`$XDG_CONFIG_HOME/iroh-rdp-tunnel/server.key`，缺省 `~/.config/...`
pub fn default_key_file() -> PathBuf {
    config_dir().join("server.key")
}

/// 控制端私钥文件默认路径。
pub fn default_client_key_file() -> PathBuf {
    config_dir().join("client.key")
}

/// rustp2p 身份文件默认路径（被控端）。
pub fn default_rustp2p_identity_file() -> PathBuf {
    config_dir().join("rustp2p-server.json")
}

/// rustp2p 身份文件默认路径（控制端）。
pub fn default_client_rustp2p_identity_file() -> PathBuf {
    config_dir().join("rustp2p-client.json")
}

/// 配置目录。
fn config_dir() -> PathBuf {
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join("AppData").join("Roaming"))
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join(".config"))
    };
    base.join("iroh-rdp-tunnel")
}

/// 用户主目录。
fn home_dir() -> PathBuf {
    if cfg!(windows) {
        std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
    } else {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

/// 被控端本机 RDP 默认地址。
pub fn default_rdp_target() -> SocketAddr {
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 3389)
}

/// 控制端本地监听默认地址。
pub fn default_listen() -> SocketAddr {
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 13389)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_key_file_is_absolute_and_named_server_key() {
        let p = default_key_file();
        assert!(p.is_absolute(), "密钥文件路径必须是绝对路径，实际: {p:?}");
        assert_eq!(
            p.file_name().and_then(|s| s.to_str()),
            Some("server.key"),
            "密钥文件名必须是 server.key，实际: {p:?}"
        );
        assert!(
            p.to_string_lossy().contains("iroh-rdp-tunnel"),
            "密钥文件应放在 iroh-rdp-tunnel 目录下，实际: {p:?}"
        );
    }

    #[test]
    fn default_client_key_file_is_absolute_and_named_client_key() {
        let p = default_client_key_file();
        assert!(p.is_absolute(), "必须是绝对路径，实际: {p:?}");
        assert_eq!(p.file_name().and_then(|s| s.to_str()), Some("client.key"));
        assert!(
            p.to_string_lossy().contains("iroh-rdp-tunnel"),
            "实际: {p:?}"
        );
        assert_ne!(
            p, default_key_file(),
            "客户端与被控端必须用不同的密钥文件，否则 endpoint id 会撞车"
        );
    }

    #[test]
    fn default_rdp_target_is_loopback_3389() {
        assert_eq!(default_rdp_target().to_string(), "127.0.0.1:3389");
    }

    #[test]
    fn default_listen_is_loopback_13389() {
        assert_eq!(default_listen().to_string(), "127.0.0.1:13389");
    }

    #[test]
    fn env_source_reads_pairs() {
        let env = EnvSource::from_pairs(&[("IRT_PUBLISH", "ip")]);
        assert_eq!(env.get("IRT_PUBLISH"), Some("ip"));
        assert_eq!(env.get("IRT_MISSING"), None);
    }

    #[test]
    fn env_source_treats_blank_value_as_unset() {
        let env = EnvSource::from_pairs(&[("IRT_PUBLISH", "   ")]);
        assert_eq!(env.get("IRT_PUBLISH"), None);
    }

    #[test]
    fn env_source_splits_comma_lists() {
        let env = EnvSource::from_pairs(&[("IRT_ALLOW", " aa , ,bb ")]);
        assert_eq!(env.get_list("IRT_ALLOW"), vec!["aa".to_string(), "bb".to_string()]);
    }
}
