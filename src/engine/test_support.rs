// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
#[cfg(any(feature = "daemon", feature = "pcap"))]
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::anyhow;

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
use crate::domain::policy::{TrafficPlan, TrafficPolicy, TransmissionPolicy};
#[cfg(feature = "daemon")]
use crate::domain::request::ListenerRequest;
use crate::domain::spec::{ListenerSpec, LoggingSpec, PacketSpec, TransmissionSpec};
use crate::domain::transmission::{
    DestinationSelectionReason, InterfaceSelectionReason, PlanningMode, SourceSelectionReason,
    TransmissionLinkType, TransmissionPlan, TransmissionProtocol, TransmissionSelection,
    TransmissionSummary, TransmissionTarget,
};
#[cfg(feature = "daemon")]
use crate::engine::ports::DaemonListenerRuntime;
use crate::engine::ports::{
    DnsClient, EngineOutput, ListenerEventHandler, ListenerRunner, PacketPlanner,
    PacketTransmitter, PortFuture, PortResult, PreparedDnsQuery, PrivilegeChecker,
    RuleActionTelemetry, TargetResolver,
};
#[cfg(feature = "fuzz")]
use crate::engine::ports::{FuzzRunner, GeneratedPacketSender, PreparedFuzzRun};
#[cfg(feature = "scan")]
use crate::engine::ports::{PreparedScanRun, ScanRunner};
#[cfg(feature = "traceroute")]
use crate::engine::ports::{PreparedTracerouteRun, TracerouteRunner};

fn reject_future<T>(message: &'static str) -> PortFuture<T> {
    Box::pin(async move { Err(anyhow!(message)) })
}

pub(crate) fn ipv4_udp_transmission_plan(mode: PlanningMode) -> TransmissionPlan {
    TransmissionPlan {
        frames: vec![vec![0; 4]],
        link_type: TransmissionLinkType::Ipv4,
        transmit: TransmissionSpec::default(),
        destination: TransmissionTarget::Ipv4(Ipv4Addr::new(192, 0, 2, 10)),
        interface_name: "eth-test".to_string(),
        selection: TransmissionSelection {
            selected_interface: "eth-test".to_string(),
            interface_reason: InterfaceSelectionReason::ExplicitInterface,
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
            source_reason: SourceSelectionReason::ExplicitSourceIp,
            destination_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            destination_reason: DestinationSelectionReason::TargetLiteral,
        },
        protocol: TransmissionProtocol(17),
        summary: TransmissionSummary {
            payload_len: 0,
            largest_frame_len: 4,
            frame_count: 1,
            transport: "udp",
        },
        logging: LoggingSpec::default(),
        mode,
        policy: TransmissionPolicy::default(),
    }
}

pub(crate) struct NoOpOutput;

impl EngineOutput for NoOpOutput {
    fn emit_preflight_summary(
        &self,
        _spec: &PacketSpec,
        _plan: &TransmissionPlan,
    ) -> PortResult<()> {
        Ok(())
    }

    #[cfg(any(feature = "scan", feature = "traceroute", feature = "fuzz"))]
    fn emit_traffic_plan_summary(&self, _plan: &TrafficPlan) -> PortResult<()> {
        Ok(())
    }

    fn emit_listener_event(&self, _event: &ListenerEvent) {}

    fn emit_text_output(&self, _rendered: &str) -> PortResult<()> {
        Ok(())
    }

    fn format_dns_dry_run(&self, _request: &DnsRequest) -> PortResult<String> {
        Ok(String::new())
    }

    fn format_dns_response(&self, _result: &DnsQueryResult) -> PortResult<String> {
        Ok(String::new())
    }
}

pub(crate) struct RejectTargetResolver;

impl TargetResolver for RejectTargetResolver {
    fn resolve_target_ip(&self, _target: String, _prefer_ipv6: Option<bool>) -> PortFuture<IpAddr> {
        reject_future("target resolver should not be used")
    }
}

pub(crate) struct AllowPrivilegeChecker;

impl PrivilegeChecker for AllowPrivilegeChecker {
    fn check_packet_send(&self, _spec: Arc<PacketSpec>) -> PortFuture<()> {
        Box::pin(async { Ok(()) })
    }
}

pub(crate) struct RejectPrivilegeChecker;

impl PrivilegeChecker for RejectPrivilegeChecker {
    fn check_packet_send(&self, _spec: Arc<PacketSpec>) -> PortFuture<()> {
        reject_future("privilege checker should not be used")
    }
}

pub(crate) struct RejectPacketPlanner;

impl PacketPlanner for RejectPacketPlanner {
    fn plan_packet(
        &self,
        _spec: Arc<PacketSpec>,
        _mode: PlanningMode,
        _policy: TransmissionPolicy,
    ) -> PortFuture<TransmissionPlan> {
        reject_future("packet planner should not be used")
    }
}

pub(crate) struct RejectPacketTransmitter;

impl PacketTransmitter for RejectPacketTransmitter {
    fn transmit(&self, _plan: TransmissionPlan) -> PortFuture<()> {
        reject_future("packet transmitter should not be used")
    }
}

pub(crate) struct RejectListenerRunner;

impl ListenerRunner for RejectListenerRunner {
    #[cfg(not(feature = "pcap"))]
    fn run_for_packet(
        &self,
        _spec: ListenerSpec,
        _interface_hint: Option<String>,
        _handler: ListenerEventHandler,
    ) -> PortFuture<()> {
        reject_future("listener runner should not be used")
    }

    #[cfg(feature = "pcap")]
    fn run_for_packet_with_lifecycle(
        &self,
        _spec: ListenerSpec,
        _interface_hint: Option<String>,
        _handler: ListenerEventHandler,
        _shutdown: Arc<AtomicBool>,
        _startup: Option<crate::engine::ports::ListenerStartupSignal>,
    ) -> PortFuture<()> {
        reject_future("listener lifecycle runner should not be used")
    }

    #[cfg(feature = "pcap")]
    fn run_command(
        &self,
        _request: ListenRequest,
        _handler: ListenerEventHandler,
    ) -> PortFuture<()> {
        reject_future("listener command should not be used")
    }
}

#[cfg(feature = "daemon")]
pub(crate) struct RejectDaemonListenerRuntime;

#[cfg(feature = "daemon")]
impl DaemonListenerRuntime for RejectDaemonListenerRuntime {
    fn validate_options(&self, _options: &ListenerRequest) -> PortResult<()> {
        Err(anyhow!("daemon listener runtime should not be used"))
    }

    fn spawn_background(
        &self,
        _options: ListenerRequest,
        _interface_hint: Option<String>,
        _handler: ListenerEventHandler,
        _shutdown: Arc<AtomicBool>,
        _startup: Option<crate::engine::ports::ListenerStartupSignal>,
    ) -> PortResult<tokio::task::JoinHandle<PortResult<()>>> {
        Err(anyhow!("daemon listener runtime should not be used"))
    }
}

pub(crate) struct RejectDnsClient;

impl DnsClient for RejectDnsClient {
    fn prepare(
        &self,
        _request: DnsRequest,
        _policy: TrafficPolicy,
    ) -> PortFuture<PreparedDnsQuery> {
        reject_future("dns client should not be used")
    }
}

#[cfg(feature = "traceroute")]
pub(crate) struct RejectTracerouteRunner;

#[cfg(feature = "traceroute")]
impl TracerouteRunner for RejectTracerouteRunner {
    fn prepare(
        &self,
        _request: TracerouteRequest,
        _policy: TrafficPolicy,
    ) -> PortFuture<PreparedTracerouteRun> {
        reject_future("traceroute runner should not be used")
    }
}

#[cfg(feature = "scan")]
pub(crate) struct RejectScanRunner;

#[cfg(feature = "scan")]
impl ScanRunner for RejectScanRunner {
    fn prepare(
        &self,
        _request: ScanRequest,
        _policy: TrafficPolicy,
    ) -> PortFuture<PreparedScanRun> {
        reject_future("scan runner should not be used")
    }
}

#[cfg(feature = "fuzz")]
pub(crate) struct RejectFuzzRunner;

#[cfg(feature = "fuzz")]
impl FuzzRunner for RejectFuzzRunner {
    fn prepare(
        &self,
        _request: FuzzRequest,
        _policy: TrafficPolicy,
        _sender: GeneratedPacketSender,
    ) -> PortFuture<PreparedFuzzRun> {
        reject_future("fuzz runner should not be used")
    }
}

pub(crate) struct NoOpRuleActionTelemetry;

impl RuleActionTelemetry for NoOpRuleActionTelemetry {
    fn record_rule_action(&self, _action: &'static str, _status: &'static str) {}

    fn record_rule_executor_drop(&self, _action: &'static str, _reason: &'static str) {}
}
