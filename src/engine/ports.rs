// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
#[cfg(feature = "daemon")]
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::Error;

#[cfg(feature = "fuzz")]
use crate::domain::command::FuzzRequest;
#[cfg(feature = "pcap")]
use crate::domain::command::ListenRequest;
#[cfg(feature = "scan")]
use crate::domain::command::ScanRequest;
#[cfg(feature = "traceroute")]
use crate::domain::command::TracerouteRequest;
use crate::domain::command::{DnsQueryResult, DnsRequest};
use crate::domain::event::ListenerEvent;
use crate::domain::policy::TrafficPlan;
use crate::domain::policy::TrafficPolicy;
use crate::domain::policy::TransmissionPolicy;
#[cfg(feature = "daemon")]
use crate::domain::request::ListenerRequest;
use crate::domain::request::PacketRequest;
use crate::domain::spec::{ListenerSpec, PacketSpec};
use crate::domain::transmission::{PlanningMode, TransmissionPlan};

pub(crate) type PortResult<T> = Result<T, Error>;
pub(crate) type PortFuture<T> = Pin<Box<dyn Future<Output = PortResult<T>> + Send + 'static>>;
type PreparedDnsResolver = Box<dyn FnOnce() -> PortFuture<DnsQueryResult> + Send + 'static>;
#[cfg(any(feature = "scan", feature = "traceroute", feature = "fuzz"))]
type PreparedTrafficExecutor = Box<dyn FnOnce() -> PortFuture<()> + Send + 'static>;
#[cfg(feature = "fuzz")]
pub(crate) type GeneratedPacketSender =
    Arc<dyn Fn(PacketSpec) -> PortFuture<()> + Send + Sync + 'static>;

pub(crate) struct PreparedDnsQuery {
    traffic_plan: TrafficPlan,
    resolver: PreparedDnsResolver,
}

impl PreparedDnsQuery {
    pub(crate) fn new(traffic_plan: TrafficPlan, resolver: PreparedDnsResolver) -> Self {
        Self {
            traffic_plan,
            resolver,
        }
    }

    pub(crate) fn traffic_plan(&self) -> &TrafficPlan {
        &self.traffic_plan
    }

    pub(crate) fn resolve(self) -> PortFuture<DnsQueryResult> {
        (self.resolver)()
    }
}

#[cfg(any(feature = "scan", feature = "traceroute", feature = "fuzz"))]
pub(crate) struct PreparedTrafficRun {
    traffic_plan: TrafficPlan,
    executor: PreparedTrafficExecutor,
}

#[cfg(any(feature = "scan", feature = "traceroute", feature = "fuzz"))]
impl PreparedTrafficRun {
    pub(crate) fn new(traffic_plan: TrafficPlan, executor: PreparedTrafficExecutor) -> Self {
        Self {
            traffic_plan,
            executor,
        }
    }

    pub(crate) fn traffic_plan(&self) -> &TrafficPlan {
        &self.traffic_plan
    }

    pub(crate) fn run(self) -> PortFuture<()> {
        (self.executor)()
    }
}

#[cfg(feature = "traceroute")]
pub(crate) type PreparedTracerouteRun = PreparedTrafficRun;

#[cfg(feature = "scan")]
pub(crate) type PreparedScanRun = PreparedTrafficRun;

#[cfg(feature = "fuzz")]
pub(crate) type PreparedFuzzRun = PreparedTrafficRun;

pub(crate) trait TargetResolver: Send + Sync {
    fn resolve_target_ip(&self, target: String, prefer_ipv6: Option<bool>) -> PortFuture<IpAddr>;
}

pub(crate) trait PrivilegeChecker: Send + Sync {
    fn check_packet_send(&self, spec: Arc<PacketSpec>) -> PortFuture<()>;
}

pub(crate) trait PacketPlanner: Send + Sync {
    fn plan_packet(
        &self,
        spec: Arc<PacketSpec>,
        mode: PlanningMode,
        policy: TransmissionPolicy,
    ) -> PortFuture<TransmissionPlan>;
}

pub(crate) trait PacketTransmitter: Send + Sync {
    fn transmit(&self, plan: TransmissionPlan) -> PortFuture<()>;
}

pub(crate) trait ListenerRunner: Send + Sync {
    fn run_for_packet(
        &self,
        spec: ListenerSpec,
        interface_hint: Option<String>,
        handler: ListenerEventHandler,
    ) -> PortFuture<()>;

    #[cfg(feature = "pcap")]
    fn run_command(&self, request: ListenRequest, handler: ListenerEventHandler) -> PortFuture<()>;
}

pub(crate) type ListenerEventHandler = Arc<dyn Fn(ListenerEvent) + Send + Sync>;

#[cfg(feature = "daemon")]
pub(crate) type ListenerStartupSignal = tokio::sync::oneshot::Sender<Result<(), String>>;

#[cfg(feature = "daemon")]
pub(crate) trait DaemonListenerRuntime: Send + Sync {
    fn validate_options(&self, options: &ListenerRequest) -> PortResult<()>;
    fn spawn_background(
        &self,
        options: ListenerRequest,
        interface_hint: Option<String>,
        handler: ListenerEventHandler,
        shutdown: Arc<AtomicBool>,
        startup: Option<ListenerStartupSignal>,
    ) -> PortResult<tokio::task::JoinHandle<PortResult<()>>>;
}

pub(crate) trait DnsClient: Send + Sync {
    fn prepare(&self, request: DnsRequest, policy: TrafficPolicy) -> PortFuture<PreparedDnsQuery>;
}

#[cfg(feature = "traceroute")]
pub(crate) trait TracerouteRunner: Send + Sync {
    fn prepare(
        &self,
        request: TracerouteRequest,
        policy: TrafficPolicy,
    ) -> PortFuture<PreparedTracerouteRun>;
}

#[cfg(feature = "scan")]
pub(crate) trait ScanRunner: Send + Sync {
    fn prepare(&self, request: ScanRequest, policy: TrafficPolicy) -> PortFuture<PreparedScanRun>;
}

#[cfg(feature = "fuzz")]
pub(crate) trait FuzzRunner: Send + Sync {
    fn prepare(
        &self,
        request: FuzzRequest,
        policy: TrafficPolicy,
        sender: GeneratedPacketSender,
    ) -> PortFuture<PreparedFuzzRun>;
}

pub(crate) trait EngineOutput: Send + Sync {
    fn emit_preflight_summary(&self, spec: &PacketSpec, plan: &TransmissionPlan) -> PortResult<()>;
    #[cfg(any(feature = "scan", feature = "traceroute", feature = "fuzz"))]
    fn emit_traffic_plan_summary(&self, plan: &TrafficPlan) -> PortResult<()>;
    fn emit_listener_event(&self, event: &ListenerEvent);
    fn format_dns_dry_run(&self, request: &DnsRequest) -> PortResult<String>;
    fn format_dns_response(&self, result: &DnsQueryResult) -> PortResult<String>;
}

pub(crate) trait RuleActionTelemetry: Send + Sync {
    fn record_rule_action(&self, action: &'static str, status: &'static str);
    fn record_rule_executor_drop(&self, action: &'static str, reason: &'static str);
}

#[derive(Clone)]
pub(crate) struct EngineDependencies {
    pub target_resolver: Arc<dyn TargetResolver>,
    pub privilege_checker: Arc<dyn PrivilegeChecker>,
    pub packet_planner: Arc<dyn PacketPlanner>,
    pub packet_transmitter: Arc<dyn PacketTransmitter>,
    pub listener_runner: Arc<dyn ListenerRunner>,
    #[cfg(feature = "daemon")]
    pub daemon_listener_runtime: Arc<dyn DaemonListenerRuntime>,
    pub dns_client: Arc<dyn DnsClient>,
    #[cfg(feature = "traceroute")]
    pub traceroute_runner: Arc<dyn TracerouteRunner>,
    #[cfg(feature = "scan")]
    pub scan_runner: Arc<dyn ScanRunner>,
    #[cfg(feature = "fuzz")]
    pub fuzz_runner: Arc<dyn FuzzRunner>,
    pub output: Arc<dyn EngineOutput>,
    pub rule_action_telemetry: Arc<dyn RuleActionTelemetry>,
}

impl std::fmt::Debug for EngineDependencies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineDependencies").finish_non_exhaustive()
    }
}

pub(crate) fn resolve_packet_request(
    mut request: PacketRequest,
    resolver: Arc<dyn TargetResolver>,
) -> PortFuture<PacketRequest> {
    Box::pin(async move {
        if request.destination.destination_ip.is_none() {
            if let Some(target) = request.destination.destination.as_deref() {
                let trimmed = target.trim();
                if !trimmed.is_empty() && trimmed.parse::<IpAddr>().is_err() {
                    let resolved = resolver
                        .resolve_target_ip(trimmed.to_string(), request.prefer_ipv6_hint())
                        .await?;
                    request.destination.resolved_destination = Some(resolved);
                }
            }
        }

        Ok(request)
    })
}
