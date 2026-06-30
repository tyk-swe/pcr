// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "fuzz")]
use crate::domain::command::FuzzRequest;
#[cfg(feature = "scan")]
use crate::domain::command::ScanRequest;
#[cfg(feature = "traceroute")]
use crate::domain::command::TracerouteRequest;
use crate::domain::command::{DnsQueryResult, DnsRequest};
use crate::domain::policy::TrafficPolicy;
use crate::engine::ports::{DnsClient, PortFuture, PreparedDnsQuery};
#[cfg(feature = "fuzz")]
use crate::engine::ports::{FuzzRunner, PreparedFuzzRun};
#[cfg(feature = "scan")]
use crate::engine::ports::{PreparedScanRun, ScanRunner};
#[cfg(feature = "traceroute")]
use crate::engine::ports::{PreparedTracerouteRun, TracerouteRunner};

#[derive(Debug, Default)]
pub(crate) struct ToolsDnsClient;

impl DnsClient for ToolsDnsClient {
    fn prepare(&self, request: DnsRequest, policy: TrafficPolicy) -> PortFuture<PreparedDnsQuery> {
        Box::pin(async move {
            let prepared = crate::tools::dns::prepare(&request, policy).await?;
            let traffic_plan = prepared.traffic_plan.clone();
            let resolver = Box::new(move || {
                Box::pin(
                    async move { crate::tools::dns::resolve_prepared(&request, prepared).await },
                ) as PortFuture<DnsQueryResult>
            });

            Ok(PreparedDnsQuery::new(traffic_plan, resolver))
        })
    }
}

#[cfg(feature = "traceroute")]
#[derive(Debug, Default)]
pub(crate) struct ToolsTracerouteRunner;

#[cfg(feature = "traceroute")]
impl TracerouteRunner for ToolsTracerouteRunner {
    fn prepare(
        &self,
        request: TracerouteRequest,
        policy: TrafficPolicy,
    ) -> PortFuture<PreparedTracerouteRun> {
        Box::pin(async move {
            let prepared = crate::tools::traceroute::prepare(&request, policy)?;
            let traffic_plan = prepared.traffic_plan.clone();
            let executor = Box::new(move || {
                Box::pin(
                    async move { crate::tools::traceroute::run_prepared(&request, prepared).await },
                ) as PortFuture<()>
            });
            Ok(PreparedTracerouteRun::new(traffic_plan, executor))
        })
    }
}

#[cfg(feature = "scan")]
#[derive(Debug, Default)]
pub(crate) struct ToolsScanRunner;

#[cfg(feature = "scan")]
impl ScanRunner for ToolsScanRunner {
    fn prepare(&self, request: ScanRequest, policy: TrafficPolicy) -> PortFuture<PreparedScanRun> {
        Box::pin(async move {
            let prepared = crate::tools::scan::prepare(&request, policy)?;
            let traffic_plan = prepared.traffic_plan.clone();
            let runtime = crate::tools::TrafficRuntimeConfig::from_policy(&policy);
            let executor = Box::new(move || {
                Box::pin(async move {
                    crate::tools::scan::run_command(prepared.command(), runtime).await
                }) as PortFuture<()>
            });
            Ok(PreparedScanRun::new(traffic_plan, executor))
        })
    }
}

#[cfg(feature = "fuzz")]
#[derive(Debug, Default)]
pub(crate) struct ToolsFuzzRunner;

#[cfg(feature = "fuzz")]
impl FuzzRunner for ToolsFuzzRunner {
    fn prepare(&self, request: FuzzRequest, policy: TrafficPolicy) -> PortFuture<PreparedFuzzRun> {
        Box::pin(async move {
            let config = fuzz_config_for_policy(&request, &policy)?;
            let traffic_plan = crate::tools::fuzz::traffic_plan(&config)?;
            let executor = Box::new(move || {
                Box::pin(async move {
                    crate::tools::fuzz::run_fuzz(config).await?;
                    Ok(())
                }) as PortFuture<()>
            });
            Ok(PreparedFuzzRun::new(traffic_plan, executor))
        })
    }
}

#[cfg(feature = "fuzz")]
fn fuzz_config_for_policy(
    request: &FuzzRequest,
    policy: &TrafficPolicy,
) -> anyhow::Result<crate::tools::fuzz::FuzzConfig> {
    let mut config = crate::tools::fuzz::FuzzConfig::try_from(request)?;
    config.apply_traffic_policy(policy);
    Ok(config)
}
