// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use log::{error, info, warn};
use tokio::runtime::Handle;

use crate::domain::policy::TrafficPolicy;
use crate::domain::request::PacketRequest;
use crate::engine::ports::RuleActionTelemetry;
use crate::engine::send::SendUseCase;
use crate::rules::{
    validate_rule_send_request, BoundedExecutor, ExecutorError, PacketContext, RuleActionError,
    RuleError, RuleSendDispatcher, RuleSendTemplate,
};

const RULE_SEND_EXECUTOR_WORKERS: usize = 4;
const RULE_SEND_EXECUTOR_QUEUE_CAPACITY: usize = 64;

type Result<T> = std::result::Result<T, RuleError>;

#[derive(Debug, Clone)]
pub(crate) struct RuleSendConfig {
    workers: usize,
    queue_capacity: usize,
    traffic_policy: TrafficPolicy,
    dry_run: bool,
}

impl RuleSendConfig {
    pub(crate) fn from_options(
        workers: Option<usize>,
        queue_capacity: Option<usize>,
        traffic_policy: TrafficPolicy,
        dry_run: bool,
    ) -> Self {
        Self {
            workers: workers.unwrap_or(RULE_SEND_EXECUTOR_WORKERS),
            queue_capacity: queue_capacity.unwrap_or(RULE_SEND_EXECUTOR_QUEUE_CAPACITY),
            traffic_policy: traffic_policy.with_dry_run(dry_run),
            dry_run,
        }
    }
}

#[derive(Clone)]
pub(crate) struct RuleSendExecutor {
    executor: Arc<BoundedExecutor>,
    send: Arc<SendUseCase>,
    telemetry: Arc<dyn RuleActionTelemetry>,
    traffic_policy: TrafficPolicy,
    dry_run: bool,
}

impl RuleSendExecutor {
    pub(crate) fn new_configured(
        config: RuleSendConfig,
        send: Arc<SendUseCase>,
        telemetry: Arc<dyn RuleActionTelemetry>,
    ) -> Result<Self> {
        let executor = BoundedExecutor::new(
            "rule-send-worker",
            config.workers,
            config.workers + config.queue_capacity,
        )?;
        Ok(Self::from_executor(config, send, telemetry, executor))
    }

    pub(crate) fn new_configured_with_runtime_handle(
        config: RuleSendConfig,
        send: Arc<SendUseCase>,
        telemetry: Arc<dyn RuleActionTelemetry>,
        handle: Handle,
    ) -> Result<Self> {
        let executor = BoundedExecutor::new_with_handle(
            handle,
            config.workers,
            config.workers + config.queue_capacity,
        )?;
        Ok(Self::from_executor(config, send, telemetry, executor))
    }

    fn from_executor(
        config: RuleSendConfig,
        send: Arc<SendUseCase>,
        telemetry: Arc<dyn RuleActionTelemetry>,
        executor: BoundedExecutor,
    ) -> Self {
        Self {
            executor: Arc::new(executor),
            send,
            telemetry,
            traffic_policy: config.traffic_policy,
            dry_run: config.dry_run,
        }
    }

    fn transmission_policy(&self) -> TrafficPolicy {
        self.traffic_policy.with_dry_run(self.dry_run)
    }

    async fn send(rule_name: String, request: PacketRequest, send: Arc<SendUseCase>) -> Result<()> {
        let prepared =
            send.prepare(request, true)
                .await
                .map_err(|source| RuleActionError::SendExecution {
                    rule: rule_name.clone(),
                    stage: "preparing packet send",
                    source,
                })?;
        send.execute_plan(prepared.plan).await.map_err(|source| {
            RuleActionError::SendExecution {
                rule: rule_name,
                stage: "executing transmission",
                source,
            }
        })?;
        Ok(())
    }
}

impl std::fmt::Debug for RuleSendExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleSendExecutor")
            .field("traffic_policy", &self.traffic_policy)
            .field("dry_run", &self.dry_run)
            .finish_non_exhaustive()
    }
}

impl RuleSendDispatcher for RuleSendExecutor {
    fn dispatch(
        &self,
        rule_name: &str,
        template: &RuleSendTemplate,
        packet: Option<&PacketContext>,
    ) -> Result<()> {
        let rendered = template.render(packet);
        let policy = self.transmission_policy();
        validate_rule_send_request(rule_name, &rendered, policy)?;

        if self.dry_run {
            info!(
                "rule '{}' send action validated (dry-run); would dispatch templated packet",
                rule_name
            );
            self.telemetry
                .record_rule_action("send", "dry_run_validated");
            return Ok(());
        }

        let rule_name_owned = rule_name.to_string();
        let send = Arc::clone(&self.send);
        let telemetry = Arc::clone(&self.telemetry);
        let spawn_result = self.executor.spawn_async(move || async move {
            telemetry.record_rule_action("send", "started");
            match Self::send(rule_name_owned.clone(), rendered, send).await {
                Ok(_) => {
                    telemetry.record_rule_action("send", "succeeded");
                    info!("rule '{}' dispatched templated packet", rule_name_owned)
                }
                Err(err) => {
                    telemetry.record_rule_action("send", "failed");
                    error!("rule '{}' send action failed: {err}", rule_name_owned)
                }
            }
        });

        self.handle_spawn_result(rule_name, spawn_result)
    }
}

impl RuleSendExecutor {
    fn handle_spawn_result(
        &self,
        rule_name: &str,
        spawn_result: std::result::Result<(), ExecutorError>,
    ) -> Result<()> {
        match spawn_result {
            Ok(()) => {
                self.telemetry.record_rule_action("send", "queued");
                Ok(())
            }
            Err(ExecutorError::QueueFull) => {
                warn!(
                    "rule '{}' send action dropped: executor queue is full",
                    rule_name
                );
                self.telemetry
                    .record_rule_executor_drop("send", "queue_full");
                Err(RuleActionError::SendQueueFull {
                    rule: rule_name.to_string(),
                }
                .into())
            }
            Err(ExecutorError::Closed) => {
                error!(
                    "rule '{}' send action failed: executor unavailable",
                    rule_name
                );
                self.telemetry
                    .record_rule_executor_drop("send", "executor_closed");
                Err(RuleActionError::SendExecutorUnavailable {
                    rule: rule_name.to_string(),
                }
                .into())
            }
            Err(ExecutorError::RuntimeUnavailable(details)) => {
                error!(
                    "rule '{}' send action failed: executor runtime unavailable: {}",
                    rule_name, details
                );
                self.telemetry
                    .record_rule_executor_drop("send", "runtime_unavailable");
                Err(RuleActionError::SendExecutorUnavailable {
                    rule: rule_name.to_string(),
                }
                .into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use anyhow::anyhow;
    use tokio::time::timeout;

    use super::*;
    use crate::domain::command::{DnsQueryResult, DnsRequest};
    use crate::domain::event::ListenerEvent;
    use crate::domain::request::{DestinationRequest, PacketRequest};
    use crate::domain::spec::{ListenerSpec, PacketSpec};
    use crate::domain::transmission::{
        DestinationSelectionReason, InterfaceSelectionReason, PlanningMode, SourceSelectionReason,
        TransmissionLinkType, TransmissionPlan, TransmissionProtocol, TransmissionSelection,
        TransmissionSummary, TransmissionTarget,
    };
    #[cfg(feature = "daemon")]
    use crate::engine::ports::DaemonListenerRuntime;
    use crate::engine::ports::{
        DnsClient, EngineDependencies, EngineOutput, ListenerEventHandler, ListenerRunner,
        PacketPlanner, PacketTransmitter, PortFuture, PreparedDnsQuery, PrivilegeChecker,
        RuleActionTelemetry, TargetResolver,
    };
    #[cfg(feature = "fuzz")]
    use crate::engine::ports::{FuzzRunner, GeneratedPacketSender, PreparedFuzzRun};
    #[cfg(feature = "scan")]
    use crate::engine::ports::{PreparedScanRun, ScanRunner};
    #[cfg(feature = "traceroute")]
    use crate::engine::ports::{PreparedTracerouteRun, TracerouteRunner};

    #[derive(Default)]
    struct TelemetryState {
        actions: Mutex<Vec<(&'static str, &'static str)>>,
        drops: Mutex<Vec<(&'static str, &'static str)>>,
    }

    impl TelemetryState {
        fn has_action(&self, action: &'static str, status: &'static str) -> bool {
            self.actions.lock().unwrap().contains(&(action, status))
        }

        fn has_drop(&self, action: &'static str, reason: &'static str) -> bool {
            self.drops.lock().unwrap().contains(&(action, reason))
        }
    }

    #[derive(Default)]
    struct RecordingTelemetry {
        state: Arc<TelemetryState>,
    }

    impl RuleActionTelemetry for RecordingTelemetry {
        fn record_rule_action(&self, action: &'static str, status: &'static str) {
            self.state.actions.lock().unwrap().push((action, status));
        }

        fn record_rule_executor_drop(&self, action: &'static str, reason: &'static str) {
            self.state.drops.lock().unwrap().push((action, reason));
        }
    }

    #[derive(Clone, Copy)]
    enum TransmitMode {
        Success,
        Fail,
    }

    struct FakePacketPlanner;

    impl PacketPlanner for FakePacketPlanner {
        fn plan_packet(
            &self,
            _spec: Arc<PacketSpec>,
            _mode: PlanningMode,
            _policy: crate::domain::policy::TransmissionPolicy,
        ) -> PortFuture<TransmissionPlan> {
            Box::pin(async { Ok(transmission_plan()) })
        }
    }

    struct FakePacketTransmitter {
        mode: TransmitMode,
    }

    impl PacketTransmitter for FakePacketTransmitter {
        fn transmit(&self, _plan: TransmissionPlan) -> PortFuture<()> {
            let mode = self.mode;
            Box::pin(async move {
                match mode {
                    TransmitMode::Success => Ok(()),
                    TransmitMode::Fail => Err(anyhow!("send failed")),
                }
            })
        }
    }

    struct NoOpOutput;

    impl EngineOutput for NoOpOutput {
        fn emit_preflight_summary(
            &self,
            _spec: &PacketSpec,
            _plan: &TransmissionPlan,
        ) -> crate::engine::ports::PortResult<()> {
            Ok(())
        }

        #[cfg(any(feature = "scan", feature = "traceroute", feature = "fuzz"))]
        fn emit_traffic_plan_summary(
            &self,
            _plan: &crate::domain::policy::TrafficPlan,
        ) -> crate::engine::ports::PortResult<()> {
            Ok(())
        }

        fn emit_listener_event(&self, _event: &ListenerEvent) {}

        fn emit_text_output(&self, _rendered: &str) -> crate::engine::ports::PortResult<()> {
            Ok(())
        }

        fn format_dns_dry_run(
            &self,
            _request: &DnsRequest,
        ) -> crate::engine::ports::PortResult<String> {
            Ok(String::new())
        }

        fn format_dns_response(
            &self,
            _result: &DnsQueryResult,
        ) -> crate::engine::ports::PortResult<String> {
            Ok(String::new())
        }
    }

    struct UnusedPorts;

    impl TargetResolver for UnusedPorts {
        fn resolve_target_ip(
            &self,
            _target: String,
            _prefer_ipv6: Option<bool>,
        ) -> PortFuture<IpAddr> {
            Box::pin(async { Err(anyhow!("target resolver should not be used")) })
        }
    }

    impl PrivilegeChecker for UnusedPorts {
        fn check_packet_send(&self, _spec: Arc<PacketSpec>) -> PortFuture<()> {
            Box::pin(async { Ok(()) })
        }
    }

    impl ListenerRunner for UnusedPorts {
        #[cfg(not(feature = "pcap"))]
        fn run_for_packet(
            &self,
            _spec: ListenerSpec,
            _interface_hint: Option<String>,
            _handler: ListenerEventHandler,
        ) -> PortFuture<()> {
            Box::pin(async { Err(anyhow!("listener runner should not be used")) })
        }

        #[cfg(feature = "pcap")]
        fn run_for_packet_with_lifecycle(
            &self,
            _spec: ListenerSpec,
            _interface_hint: Option<String>,
            _handler: ListenerEventHandler,
            _shutdown: Arc<std::sync::atomic::AtomicBool>,
            _startup: Option<crate::engine::ports::ListenerStartupSignal>,
        ) -> PortFuture<()> {
            Box::pin(async { Err(anyhow!("listener lifecycle runner should not be used")) })
        }

        #[cfg(feature = "pcap")]
        fn run_command(
            &self,
            _request: crate::domain::command::ListenRequest,
            _handler: ListenerEventHandler,
        ) -> PortFuture<()> {
            Box::pin(async { Err(anyhow!("listener command should not be used")) })
        }
    }

    impl DnsClient for UnusedPorts {
        fn prepare(
            &self,
            _request: DnsRequest,
            _policy: TrafficPolicy,
        ) -> PortFuture<PreparedDnsQuery> {
            Box::pin(async { Err(anyhow!("dns client should not be used")) })
        }
    }

    #[cfg(feature = "traceroute")]
    impl TracerouteRunner for UnusedPorts {
        fn prepare(
            &self,
            _request: crate::domain::command::TracerouteRequest,
            _policy: TrafficPolicy,
        ) -> PortFuture<PreparedTracerouteRun> {
            Box::pin(async { Err(anyhow!("traceroute runner should not be used")) })
        }
    }

    #[cfg(feature = "scan")]
    impl ScanRunner for UnusedPorts {
        fn prepare(
            &self,
            _request: crate::domain::command::ScanRequest,
            _policy: TrafficPolicy,
        ) -> PortFuture<PreparedScanRun> {
            Box::pin(async { Err(anyhow!("scan runner should not be used")) })
        }
    }

    #[cfg(feature = "fuzz")]
    impl FuzzRunner for UnusedPorts {
        fn prepare(
            &self,
            _request: crate::domain::command::FuzzRequest,
            _policy: TrafficPolicy,
            _sender: GeneratedPacketSender,
        ) -> PortFuture<PreparedFuzzRun> {
            Box::pin(async { Err(anyhow!("fuzz runner should not be used")) })
        }
    }

    #[cfg(feature = "daemon")]
    impl DaemonListenerRuntime for UnusedPorts {
        fn validate_options(
            &self,
            _options: &crate::domain::request::ListenerRequest,
        ) -> crate::engine::ports::PortResult<()> {
            Err(anyhow!("daemon listener runtime should not be used"))
        }

        fn spawn_background(
            &self,
            _options: crate::domain::request::ListenerRequest,
            _interface_hint: Option<String>,
            _handler: ListenerEventHandler,
            _shutdown: Arc<std::sync::atomic::AtomicBool>,
            _startup: Option<crate::engine::ports::ListenerStartupSignal>,
        ) -> crate::engine::ports::PortResult<
            tokio::task::JoinHandle<crate::engine::ports::PortResult<()>>,
        > {
            Err(anyhow!("daemon listener runtime should not be used"))
        }
    }

    impl RuleActionTelemetry for UnusedPorts {
        fn record_rule_action(&self, _action: &'static str, _status: &'static str) {}

        fn record_rule_executor_drop(&self, _action: &'static str, _reason: &'static str) {}
    }

    fn request() -> PacketRequest {
        PacketRequest {
            destination: DestinationRequest {
                destination_ip: Some("192.0.2.10".to_string()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn transmission_plan() -> TransmissionPlan {
        TransmissionPlan {
            frames: vec![vec![0; 4]],
            link_type: TransmissionLinkType::Ipv4,
            transmit: crate::domain::spec::TransmissionSpec::default(),
            destination: TransmissionTarget::Ipv4("192.0.2.10".parse().unwrap()),
            interface_name: "eth-test".to_string(),
            selection: TransmissionSelection {
                selected_interface: "eth-test".to_string(),
                interface_reason: InterfaceSelectionReason::ExplicitInterface,
                source_ip: "192.0.2.5".parse().unwrap(),
                source_reason: SourceSelectionReason::ExplicitSourceIp,
                destination_ip: "192.0.2.10".parse().unwrap(),
                destination_reason: DestinationSelectionReason::TargetLiteral,
            },
            protocol: TransmissionProtocol(17),
            summary: TransmissionSummary {
                payload_len: 0,
                largest_frame_len: 4,
                frame_count: 1,
                transport: "udp",
            },
            logging: crate::domain::spec::LoggingSpec::default(),
            mode: PlanningMode::Live,
            policy: crate::domain::policy::TransmissionPolicy::default(),
        }
    }

    fn send_use_case(mode: TransmitMode) -> Arc<SendUseCase> {
        let unused = Arc::new(UnusedPorts);
        Arc::new(SendUseCase::new(
            TrafficPolicy::default(),
            EngineDependencies {
                target_resolver: unused.clone(),
                privilege_checker: unused.clone(),
                packet_planner: Arc::new(FakePacketPlanner),
                packet_transmitter: Arc::new(FakePacketTransmitter { mode }),
                listener_runner: unused.clone(),
                #[cfg(feature = "daemon")]
                daemon_listener_runtime: unused.clone(),
                dns_client: unused.clone(),
                #[cfg(feature = "traceroute")]
                traceroute_runner: unused.clone(),
                #[cfg(feature = "scan")]
                scan_runner: unused.clone(),
                #[cfg(feature = "fuzz")]
                fuzz_runner: unused.clone(),
                output: Arc::new(NoOpOutput),
                rule_action_telemetry: unused,
            },
        ))
    }

    fn executor(
        dry_run: bool,
        mode: TransmitMode,
        telemetry_state: Arc<TelemetryState>,
    ) -> RuleSendExecutor {
        let bounded = match Handle::try_current() {
            Ok(handle) => BoundedExecutor::new_with_handle(handle, 1, 2).unwrap(),
            Err(_) => BoundedExecutor::new("rule-send-test", 1, 2).unwrap(),
        };

        RuleSendExecutor::from_executor(
            RuleSendConfig::from_options(None, None, TrafficPolicy::default(), dry_run),
            send_use_case(mode),
            Arc::new(RecordingTelemetry {
                state: telemetry_state,
            }),
            bounded,
        )
    }

    async fn wait_for_action(state: &TelemetryState, status: &'static str) {
        timeout(Duration::from_secs(1), async {
            loop {
                if state.has_action("send", status) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn rule_send_config_applies_defaults_and_dry_run_to_policy() {
        let config = RuleSendConfig::from_options(None, None, TrafficPolicy::default(), true);

        assert_eq!(config.workers, RULE_SEND_EXECUTOR_WORKERS);
        assert_eq!(config.queue_capacity, RULE_SEND_EXECUTOR_QUEUE_CAPACITY);
        assert!(config.dry_run);
        assert!(config.traffic_policy.dry_run);
    }

    #[test]
    fn handle_spawn_result_maps_executor_failures_and_records_drop_telemetry() {
        let telemetry_state = Arc::new(TelemetryState::default());
        let executor = executor(false, TransmitMode::Success, Arc::clone(&telemetry_state));

        let queue_full = executor
            .handle_spawn_result("rule-a", Err(ExecutorError::QueueFull))
            .unwrap_err();
        let closed = executor
            .handle_spawn_result("rule-b", Err(ExecutorError::Closed))
            .unwrap_err();
        let runtime = executor
            .handle_spawn_result(
                "rule-c",
                Err(ExecutorError::RuntimeUnavailable(
                    "missing runtime".to_string(),
                )),
            )
            .unwrap_err();

        assert!(matches!(
            queue_full,
            RuleError::Action(RuleActionError::SendQueueFull { rule }) if rule == "rule-a"
        ));
        assert!(matches!(
            closed,
            RuleError::Action(RuleActionError::SendExecutorUnavailable { rule }) if rule == "rule-b"
        ));
        assert!(matches!(
            runtime,
            RuleError::Action(RuleActionError::SendExecutorUnavailable { rule }) if rule == "rule-c"
        ));
        assert!(telemetry_state.has_drop("send", "queue_full"));
        assert!(telemetry_state.has_drop("send", "executor_closed"));
        assert!(telemetry_state.has_drop("send", "runtime_unavailable"));
    }

    #[test]
    fn dispatch_dry_run_records_validation_without_spawning() {
        let telemetry_state = Arc::new(TelemetryState::default());
        let executor = executor(true, TransmitMode::Success, Arc::clone(&telemetry_state));

        executor
            .dispatch("dry-run", &RuleSendTemplate::new(request()), None)
            .unwrap();

        assert!(telemetry_state.has_action("send", "dry_run_validated"));
        assert!(!telemetry_state.has_action("send", "queued"));
    }

    #[tokio::test]
    async fn dispatch_live_success_records_queue_start_and_success() {
        let telemetry_state = Arc::new(TelemetryState::default());
        let executor = executor(false, TransmitMode::Success, Arc::clone(&telemetry_state));

        executor
            .dispatch("success", &RuleSendTemplate::new(request()), None)
            .unwrap();

        assert!(telemetry_state.has_action("send", "queued"));
        wait_for_action(&telemetry_state, "started").await;
        wait_for_action(&telemetry_state, "succeeded").await;
    }

    #[tokio::test]
    async fn dispatch_live_failure_records_queue_start_and_failed() {
        let telemetry_state = Arc::new(TelemetryState::default());
        let executor = executor(false, TransmitMode::Fail, Arc::clone(&telemetry_state));

        executor
            .dispatch("failure", &RuleSendTemplate::new(request()), None)
            .unwrap();

        assert!(telemetry_state.has_action("send", "queued"));
        wait_for_action(&telemetry_state, "started").await;
        wait_for_action(&telemetry_state, "failed").await;
    }
}
