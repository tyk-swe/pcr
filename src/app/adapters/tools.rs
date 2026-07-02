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
use crate::engine::ports::{FuzzRunner, GeneratedPacketSender, PreparedFuzzRun};
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
    fn prepare(
        &self,
        request: FuzzRequest,
        policy: TrafficPolicy,
        sender: GeneratedPacketSender,
    ) -> PortFuture<PreparedFuzzRun> {
        Box::pin(async move {
            let config = fuzz_config_for_policy(&request, &policy)?;
            let traffic_plan = crate::tools::fuzz::traffic_plan(&config)?;
            let executor = Box::new(move || {
                Box::pin(async move {
                    crate::tools::fuzz::run_fuzz_with_executor(config, move |spec| (sender)(spec))
                        .await?;
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

#[cfg(all(test, feature = "fuzz"))]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::domain::command::{FuzzProtocol, FuzzRequest, FuzzStrategy};
    use crate::domain::policy::{TrafficBudget, TrafficMode, TrafficPolicy};
    use crate::domain::spec::{PacketSpec, TransportSpec};
    use crate::engine::ports::{FuzzRunner, GeneratedPacketSender};

    fn request() -> FuzzRequest {
        FuzzRequest {
            target: "192.0.2.10".to_string(),
            port: Some(9000),
            protocol: FuzzProtocol::Udp,
            strategy: FuzzStrategy::RandomPayload,
            count: 2,
            delay: 0,
        }
    }

    fn no_delay_policy() -> TrafficPolicy {
        TrafficPolicy {
            budget: TrafficBudget {
                max_batch_size: 8,
                max_rate_per_sec: 0,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn tools_fuzz_runner_uses_supplied_sender_for_generated_specs() {
        let sent_specs = Arc::new(Mutex::new(Vec::<PacketSpec>::new()));
        let observed_specs = Arc::clone(&sent_specs);
        let sender: GeneratedPacketSender = Arc::new(move |spec| {
            let sent_specs = Arc::clone(&sent_specs);
            Box::pin(async move {
                sent_specs.lock().expect("test sent specs lock").push(spec);
                Ok(())
            })
        });
        let runner = ToolsFuzzRunner;

        let prepared = runner
            .prepare(request(), no_delay_policy(), sender)
            .await
            .unwrap();

        assert_eq!(prepared.traffic_plan().mode, TrafficMode::Fuzz);
        assert!(prepared.traffic_plan().malformed);

        prepared.run().await.unwrap();

        let specs = observed_specs.lock().expect("test sent specs lock");
        assert_eq!(specs.len(), 2);
        for spec in specs.iter() {
            match &spec.transport {
                TransportSpec::Udp(udp) => assert_eq!(udp.destination_port, Some(9000)),
                other => panic!("expected UDP fuzz packet, got {other:?}"),
            }
        }
    }
}
