//! `irt diag` —— 网络体检。
//!
//! 打印本机的 NAT 画像、公网端点、端口映射可用性、各中继延迟，
//! 并给出「是否预期能 P2P 直连」的判定与建议。

use std::time::Duration;

use anyhow::Result;
use iroh::{RelayMode, Watcher as _};

use crate::{
    addrpolicy::PublishPolicy,
    cli::{DiagArgs, parse_endpoint_id},
    diag::{DiagReport, render, render_json},
    endpoint::{Discovery, EndpointOptions, bind},
    lookup,
    nat::{profile_from_report, verdict},
    portmap::{self, PortMappingStatus},
};

/// 采集网络报告的超时。
const REPORT_TIMEOUT: Duration = Duration::from_secs(20);

/// 等 relay 连接的超时。
///
/// `Endpoint::online()` 是无界的：relay 不可达时它永远不会返回，
/// 体检工具必须自己兜住这个超时。
const RELAY_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

/// 端口映射探测的超时。
const PORTMAP_TIMEOUT: Duration = Duration::from_secs(10);

/// 运行网络体检。
pub async fn run(args: DiagArgs) -> Result<()> {
    // `--lookup` 是另一种模式：查**对端**公布了什么，而不是体检本机网络。
    if let Some(raw) = args.lookup.as_deref() {
        return run_lookup(raw, args.json).await;
    }

    // 端口映射探测与 net report 互不依赖，并行跑。
    let pm_task = tokio::spawn(portmap::probe());

    let endpoint = bind(EndpointOptions {
        secret_key: None,
        relay_mode: RelayMode::Default,
        publish: PublishPolicy::RelayOnly,
        // 体检用的端点不需要被任何人拨通，不该往公共 pkarr 上发布记录。
        discovery: Discovery::Disabled,
        // 端口映射单独探测，避免重复。
        portmapper: false,
        ca_tls_config: None,
    })
    .await?;

    let mut watcher = endpoint.net_report();
    let report = match tokio::time::timeout(REPORT_TIMEOUT, watcher.initialized()).await {
        Ok(report) => report,
        Err(_) => {
            eprintln!(
                "⚠ 采集网络报告超时（{} 秒），以下结论可能不完整",
                REPORT_TIMEOUT.as_secs()
            );
            iroh::unstable_net_report::NetReport::default()
        }
    };

    // 等端点连上中继，再读实际选定的 home relay —— 那才是流量真正会走的中继。
    // online() 是无界的，必须自己套超时。
    let home_relay = match tokio::time::timeout(RELAY_WAIT_TIMEOUT, endpoint.online()).await {
        Ok(()) => endpoint
            .home_relay_status()
            .get()
            .into_iter()
            .find(|s| s.is_connected())
            .map(|s| s.url().clone()),
        Err(_) => {
            eprintln!(
                "⚠ {} 秒内未连上 relay —— home relay 未知（NAT 画像与直连判定仍然有效）",
                RELAY_WAIT_TIMEOUT.as_secs()
            );
            None
        }
    };

    let pm = match tokio::time::timeout(PORTMAP_TIMEOUT, pm_task).await {
        Ok(Ok(status)) => status,
        Ok(Err(e)) => PortMappingStatus::ProbeFailed(format!("探测任务异常结束: {e}")),
        Err(_) => PortMappingStatus::ProbeFailed("探测超时".to_string()),
    };

    let mut profile = profile_from_report(&report, pm);
    profile.home_relay = home_relay;
    let verdict = verdict(&profile);
    let report = DiagReport { profile, verdict };

    if args.json {
        println!("{}", render_json(&report));
    } else {
        print!("{}", render(&report));
    }

    // 优雅关闭，否则 iroh 会报 "Endpoint dropped without calling close()"。
    endpoint.close().await;
    Ok(())
}

/// 查询对端在 n0 上公布的地址，并判定客户端能否连上。
async fn run_lookup(raw_id: &str, json: bool) -> Result<()> {
    let id = parse_endpoint_id(raw_id)?;
    let report = lookup::lookup(id).await?;
    if json {
        println!("{}", lookup::render_json(&report));
    } else {
        print!("{}", lookup::render(&report));
    }
    Ok(())
}
