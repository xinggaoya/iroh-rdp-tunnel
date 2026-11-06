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

use crate::{
    addrpolicy::PublishPolicy,
    endpoint::{Discovery, TlsTrust},
};

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
    pub allow_list: Vec<EndpointId>,
    /// 是否启用 n0 公共 pkarr / DNS。
    pub discovery: Discovery,
    /// 中继连接的 TLS 信任模式。
    pub tls_trust: TlsTrust,
}

/// 控制端配置。
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// 远端 endpoint id。
    pub remote: EndpointId,
    /// 本地「假 RDP」监听地址。
    pub listen: SocketAddr,
    /// 中继模式。
    pub relay_mode: RelayMode,
    /// 是否启用 n0 公共 DNS 解析。
    pub discovery: Discovery,
    /// 中继连接的 TLS 信任模式。
    pub tls_trust: TlsTrust,
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
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join("AppData").join("Roaming"))
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join(".config"))
    };
    base.join("iroh-rdp-tunnel").join("server.key")
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
