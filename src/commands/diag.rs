//! `irt diag` —— 网络体检。
//!
//! 打印本机的 NAT 画像、公网端点、端口映射可用性、各中继延迟，
//! 并给出「是否预期能 P2P 直连」的判定与建议。

use std::time::Duration;

use anyhow::Result;
use iroh::{RelayMode, Watcher as _};

use crate::{
    addrpolicy::PublishPolicy,
    cli::DiagArgs,
    diag::{DiagReport, render, render_json},
    endpoint::{Discovery, EndpointOptions, bind},
    nat::{profile_from_report, verdict},
    portmap::{self, PortMappingStatus},
};

/// 采集网络报告的超时。
const REPORT_TIMEOUT: Duration = Duration::from_secs(20);

/// 运行网络体检。
pub async fn run(args: DiagArgs) -> Result<()> {
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
    endpoint.online().await;
    let home_relay = endpoint
        .home_relay_status()
        .get()
        .into_iter()
        .find(|s| s.is_connected())
        .map(|s| s.url().clone());

    let pm = match pm_task.await {
        Ok(status) => status,
        Err(e) => PortMappingStatus::ProbeFailed(format!("探测任务异常结束: {e}")),
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
