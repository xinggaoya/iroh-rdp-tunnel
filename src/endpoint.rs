//! iroh 端点的组装。
//!
//! 把「用什么密钥 / 走哪些中继 / 要不要向公共 pkarr 公布地址」这些选项集中到一处，
//! server 与 client 共用同一套代码路径；集成测试也走同一套，只是把公共发现服务关掉，
//! 从而做到**不依赖外网**。

use anyhow::{Context, Result};
use iroh::{
    Endpoint, RelayMode, SecretKey,
    address_lookup::{DnsAddressLookup, PkarrPublisher},
    endpoint::PortmapperConfig,
    endpoint::presets,
    tls::CaTlsConfig,
};

use crate::{ALPN, addrpolicy::PublishPolicy};

/// 地址发布 / 解析方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Discovery {
    /// 启用 n0 公共 pkarr（发布）与 DNS（解析）。
    Public,
    /// 完全关闭地址发布与解析。
    ///
    /// 用于自建 relay（自己知道对方地址）、离线环境，或集成测试。
    Disabled,
}

/// 端点组装选项。
#[derive(Debug, Clone)]
pub struct EndpointOptions {
    /// 私钥；`None` 表示随机生成。
    pub secret_key: Option<SecretKey>,
    /// 中继模式。
    pub relay_mode: RelayMode,
    /// 地址发布策略（仅对 [`Discovery::Public`] 的 server 有效）。
    pub publish: PublishPolicy,
    /// 是否启用公共地址发现服务。
    pub discovery: Discovery,
    /// 是否尝试 UPnP / NAT-PMP / PCP 端口映射。
    ///
    /// 路由器不支持时自动跳过；EIM 映射下打洞并不依赖端口映射。
    pub portmapper: bool,
    /// 自定义 CA 信任配置；`None` 表示使用内置/系统根证书。
    ///
    /// 自建 relay 若用自签证书，把它的 CA 加进来（见 `load_ca_file`）。
    pub ca_tls_config: Option<CaTlsConfig>,
}

impl Default for EndpointOptions {
    fn default() -> Self {
        Self {
            secret_key: None,
            relay_mode: RelayMode::Default,
            publish: PublishPolicy::RelayOnly,
            discovery: Discovery::Public,
            portmapper: true,
            ca_tls_config: None,
        }
    }
}

/// 按选项绑定一个 iroh 端点。
pub async fn bind(opts: EndpointOptions) -> Result<Endpoint> {
    let mut builder = Endpoint::builder(presets::Minimal).alpns(vec![ALPN.to_vec()]);

    if let Some(key) = opts.secret_key {
        builder = builder.secret_key(key);
    }
    builder = builder.relay_mode(opts.relay_mode);
    if opts.portmapper {
        builder = builder.portmapper_config(PortmapperConfig::default());
    }
    if let Some(ca) = &opts.ca_tls_config {
        builder = builder.ca_tls_config(ca.clone());
    }

    match opts.discovery {
        Discovery::Public => {
            // 只注册**一个** publisher：若在 presets::N0 之外再追加一个，
            // 同一个 endpoint id 会在 pkarr 上出现两条竞态记录，发布内容不确定。
            builder = builder
                .address_lookup(PkarrPublisher::n0_dns().addr_filter(opts.publish.to_addr_filter()))
                .address_lookup(DnsAddressLookup::n0_dns());
        }
        Discovery::Disabled => {}
    }

    Ok(builder.bind().await?)
}

/// 只解析、不发布 —— 控制端专用。
///
/// 控制端不需要被拨通，因此不注册 publisher；但要能通过 endpoint id 解析出
/// 对方的 relay URL / IP，所以需要 DNS 解析侧。
pub async fn bind_resolver_only(opts: EndpointOptions) -> Result<Endpoint> {
    let mut builder = Endpoint::builder(presets::Minimal).alpns(vec![ALPN.to_vec()]);

    if let Some(key) = opts.secret_key {
        builder = builder.secret_key(key);
    }
    builder = builder.relay_mode(opts.relay_mode);
    if opts.portmapper {
        builder = builder.portmapper_config(PortmapperConfig::default());
    }
    if let Some(ca) = &opts.ca_tls_config {
        builder = builder.ca_tls_config(ca.clone());
    }
    if opts.discovery == Discovery::Public {
        builder = builder.address_lookup(DnsAddressLookup::n0_dns());
    }

    Ok(builder.bind().await?)
}

/// 从 PEM 文件读取额外的根证书。
///
/// 用于信任**自签证书**的自建 relay —— 这是比「跳过证书校验」更安全的做法。
pub fn load_ca_file(path: &std::path::Path) -> anyhow::Result<CaTlsConfig> {
    let data = std::fs::read(path)
        .with_context(|| format!("读取 CA 文件失败: {}", path.display()))?;
    let mut reader = std::io::BufReader::new(&data[..]);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("解析 PEM 证书失败: {}", path.display()))?;
    if certs.is_empty() {
        anyhow::bail!("CA 文件 {} 里没有找到任何 PEM 证书", path.display());
    }
    Ok(CaTlsConfig::default().with_extra_roots(certs))
}
