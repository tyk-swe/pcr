// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

#[cfg(feature = "daemon")]
use anyhow::Context;
use anyhow::Result;
use log::info;
#[cfg(feature = "daemon")]
use log::warn;
use tokio::runtime::Handle;

#[cfg(feature = "daemon")]
use crate::domain::command::DaemonRequest;
use crate::domain::command::DnsRequest;
#[cfg(feature = "fuzz")]
use crate::domain::command::FuzzRequest;
#[cfg(feature = "pcap")]
use crate::domain::command::ListenRequest;
#[cfg(feature = "scan")]
use crate::domain::command::ScanRequest;
#[cfg(feature = "traceroute")]
use crate::domain::command::TracerouteRequest;
use crate::domain::policy::TrafficPolicy;
use crate::domain::request::PacketRequest;
use crate::engine::config::EngineConfig;
use crate::engine::error::{EngineError, EngineResult};
use crate::engine::mode::ExecutionMode;
use crate::engine::oneshot::OneShotFlow;
use crate::engine::ports::EngineDependencies;
#[cfg(any(feature = "scan", feature = "traceroute", feature = "fuzz"))]
use crate::engine::ports::PreparedTrafficRun;
use crate::engine::rule_send::{RuleSendConfig, RuleSendExecutor};
use crate::engine::send::SendUseCase;
use crate::rules::RuleEngine;

pub(crate) struct Engine {
    pub(crate) config: EngineConfig,
    pub(crate) send: Arc<SendUseCase>,
    pub(crate) dependencies: EngineDependencies,
    pub(crate) rules: RuleEngine,
    #[cfg(feature = "daemon")]
    daemon_rules_preloaded: bool,
}

impl Engine {
    pub(crate) fn new_with_runtime_handle(
        config: EngineConfig,
        dependencies: EngineDependencies,
        handle: Handle,
    ) -> EngineResult<Self> {
        Self::new_with_optional_runtime_handle(config, dependencies, Some(handle))
    }

    fn new_with_optional_runtime_handle(
        config: EngineConfig,
        dependencies: EngineDependencies,
        handle: Option<Handle>,
    ) -> EngineResult<Self> {
        let rule_config =
            crate::rules::RuleExecutorConfig::from_options(config.rule_workers, config.rule_queue);
        let send_config = RuleSendConfig::from_options(
            config.send_workers,
            config.send_queue,
            config.traffic_policy,
            config.dry_run,
        );
        let send = Arc::new(SendUseCase::new(
            config.traffic_policy,
            dependencies.clone(),
        ));

        let mut rules = match handle.as_ref() {
            Some(handle) => {
                RuleEngine::new_configured_with_runtime_handle(rule_config, handle.clone())
            }
            None => RuleEngine::new_configured(rule_config),
        }
        .map_err(|e| EngineError::RuleEngineInit(e.into()))?;
        let sender = match handle {
            Some(handle) => RuleSendExecutor::new_configured_with_runtime_handle(
                send_config,
                Arc::clone(&send),
                Arc::clone(&dependencies.rule_action_telemetry),
                handle,
            ),
            None => RuleSendExecutor::new_configured(
                send_config,
                Arc::clone(&send),
                Arc::clone(&dependencies.rule_action_telemetry),
            ),
        }
        .map_err(|e| EngineError::RuleSendExecutorInit(e.into()))?;
        rules.configure_sender(sender);
        Ok(Self {
            send,
            dependencies,
            rules,
            config,
            #[cfg(feature = "daemon")]
            daemon_rules_preloaded: false,
        })
    }

    pub(crate) async fn run_one_shot(&mut self, request: PacketRequest) -> Result<()> {
        let mode = if self.config.dry_run {
            ExecutionMode::Plan
        } else {
            ExecutionMode::Live
        };
        self.run_one_shot_with_mode(request, mode).await
    }

    pub(crate) async fn run_one_shot_with_mode(
        &mut self,
        request: PacketRequest,
        mode: ExecutionMode,
    ) -> Result<()> {
        self.run_one_shot_with_policy_options(request, mode, false)
            .await
    }

    pub(crate) async fn run_one_shot_with_policy_options(
        &mut self,
        request: PacketRequest,
        mode: ExecutionMode,
        allow_unbounded_sends: bool,
    ) -> Result<()> {
        let previous_policy = self.config.traffic_policy;
        let previous_send = Arc::clone(&self.send);
        self.config.traffic_policy.allow_unbounded_sends |= allow_unbounded_sends;
        self.send = Arc::new(previous_send.with_policy_override(self.config.traffic_policy));

        let result = async {
            OneShotFlow::new(self, request, mode)
                .with_policy_validation()?
                .with_spec()
                .await?
                .with_authorized_preflight_traffic()
                .await?
                .with_rules()
                .await?
                .with_preflight()
                .await?
                .with_plan()
                .await?
                .with_startup_rules()
                .with_preflight_output()?
                .execute()
                .await
        }
        .await;

        self.config.traffic_policy = previous_policy;
        self.send = previous_send;
        result
    }

    #[cfg(feature = "daemon")]
    pub(crate) async fn run_daemon(&mut self, opts: &DaemonRequest) -> Result<()> {
        if self.config.dry_run {
            info!(
                "Dry-run: daemon mode would start with rules={:?}",
                opts.rules_file
            );
            return Ok(());
        }
        info!("Launching daemon mode");
        if !self.daemon_rules_preloaded {
            self.init_daemon_rules(opts.rules_file.as_ref())?;
            if self.rules.has_receive_triggers() {
                crate::engine::daemon::ensure_listener_feature_available()?;
            }
        }
        self.daemon_rules_preloaded = false;
        crate::engine::daemon::run(
            opts,
            &self.config,
            &mut self.rules,
            Arc::clone(&self.dependencies.output),
            Arc::clone(&self.dependencies.daemon_listener_runtime),
        )
        .await
    }

    #[cfg(feature = "daemon")]
    pub(crate) fn apply_daemon_preflight(
        &mut self,
        preflight: crate::engine::daemon::DaemonStartupPreflight,
    ) {
        self.daemon_rules_preloaded = preflight.rules_were_loaded();
        if let Some(report) = preflight.into_rules() {
            self.rules.replace_rules(report.into_rules());
        }
    }

    #[cfg(feature = "daemon")]
    fn init_daemon_rules(&mut self, rules_file: Option<&String>) -> Result<()> {
        if let Some(rules_file) = rules_file {
            self.rules
                .load_from_path(rules_file)
                .with_context(|| format!("load rule file failed: path={rules_file}"))?;
        } else {
            warn!("daemon mode started without rules; awaiting dynamic configuration");
        }
        Ok(())
    }

    #[cfg(feature = "pcap")]
    pub(crate) async fn run_listener(&mut self, opts: &ListenRequest) -> Result<()> {
        if self.config.dry_run {
            info!(
                "Dry-run: listener would run with filter={:?} timeout={:?}",
                opts.listen.filter, opts.listen.timeout
            );
            return Ok(());
        }
        info!("Running listener mode");
        self.dependencies
            .listener_runner
            .run_command(opts.clone(), self.listener_handler())
            .await
    }

    #[cfg(feature = "traceroute")]
    pub(crate) async fn run_traceroute(&mut self, opts: &TracerouteRequest) -> Result<()> {
        let policy = self.effective_policy();
        let prepared = self
            .dependencies
            .traceroute_runner
            .prepare(opts.clone(), policy)
            .await?;
        self.run_prepared_traffic(policy, prepared, EngineError::Traceroute, || {
            info!(
                "Running traceroute to {} max_ttl={} probes={}",
                opts.destination, opts.max_ttl, opts.probes
            );
        })
        .await
    }

    pub(crate) async fn run_dns_query(&mut self, options: &DnsRequest) -> Result<()> {
        let policy = self.effective_policy();
        let prepared = self
            .dependencies
            .dns_client
            .prepare(options.clone(), policy)
            .await?;
        policy.authorize(prepared.traffic_plan())?;

        if self.config.dry_run {
            info!(
                "Dry-run: DNS query for {} {} via {}",
                options.domain, options.record_type, options.server
            );
            self.dependencies.output.emit_dns_dry_run(options)?;
            return Ok(());
        }
        let result = prepared.resolve().await?;
        self.dependencies.output.emit_dns_response(&result)?;
        Ok(())
    }

    #[cfg(feature = "scan")]
    pub(crate) async fn run_scan(&mut self, command: &ScanRequest) -> Result<()> {
        let policy = self.effective_policy();
        let prepared = self
            .dependencies
            .scan_runner
            .prepare(command.clone(), policy)
            .await?;
        self.run_prepared_traffic(policy, prepared, EngineError::Scan, || {})
            .await
    }

    #[cfg(feature = "fuzz")]
    pub(crate) async fn run_fuzz(&mut self, options: &FuzzRequest) -> Result<()> {
        let policy = self.effective_policy();
        let prepared = self
            .dependencies
            .fuzz_runner
            .prepare(options.clone(), policy)
            .await?;
        self.run_prepared_traffic(policy, prepared, EngineError::TransmissionPlan, || {})
            .await
    }

    pub(crate) fn config(&self) -> &EngineConfig {
        &self.config
    }

    #[cfg(feature = "repl")]
    pub(crate) fn rule_count(&self) -> usize {
        self.rules.len()
    }

    #[cfg(feature = "repl")]
    pub(crate) fn has_receive_rules(&self) -> bool {
        self.rules.has_receive_triggers()
    }

    fn effective_policy(&self) -> TrafficPolicy {
        self.config.traffic_policy.with_dry_run(self.config.dry_run)
    }

    #[cfg(any(feature = "scan", feature = "traceroute", feature = "fuzz"))]
    async fn run_prepared_traffic(
        &self,
        policy: TrafficPolicy,
        prepared: PreparedTrafficRun,
        map_authorization_error: impl FnOnce(anyhow::Error) -> EngineError,
        log_live_run: impl FnOnce(),
    ) -> Result<()> {
        policy
            .authorize(prepared.traffic_plan())
            .map_err(|e| map_authorization_error(e.into()))?;

        if self.config.dry_run {
            self.dependencies
                .output
                .emit_traffic_plan_summary(prepared.traffic_plan())?;
            return Ok(());
        }

        log_live_run();
        prepared.run().await
    }

    pub(crate) fn listener_handler(&self) -> crate::engine::ports::ListenerEventHandler {
        let output = Arc::clone(&self.dependencies.output);
        let rules = self.rules.clone();

        Arc::new(move |event| {
            output.emit_listener_event(&event);

            if rules.is_empty() {
                return;
            }

            let context = crate::rules::PacketContext::from_listener_event(&event);
            rules.notify_receive(&context);
        })
    }
}

#[cfg(all(test, any(feature = "scan", feature = "traceroute", feature = "fuzz")))]
mod prepared_traffic_tests {
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use anyhow::anyhow;

    use super::*;
    #[cfg(feature = "pcap")]
    use crate::domain::command::ListenRequest;
    use crate::domain::command::{DnsQueryResult, DnsRequest};
    #[cfg(feature = "fuzz")]
    use crate::domain::command::{FuzzProtocol, FuzzRequest, FuzzStrategy};
    #[cfg(feature = "scan")]
    use crate::domain::command::{PortScanRequest, ScanRequest};
    #[cfg(feature = "traceroute")]
    use crate::domain::command::{TracerouteProtocol, TracerouteRequest};
    use crate::domain::event::ListenerEvent;
    use crate::domain::policy::{TargetScope, TrafficMode, TrafficPlan};
    #[cfg(feature = "daemon")]
    use crate::domain::request::ListenerRequest;
    use crate::domain::spec::{ListenerSpec, PacketSpec};
    use crate::domain::transmission::{PlanningMode, TransmissionPlan};
    #[cfg(feature = "daemon")]
    use crate::engine::ports::DaemonListenerRuntime;
    #[cfg(feature = "fuzz")]
    use crate::engine::ports::FuzzRunner;
    #[cfg(feature = "scan")]
    use crate::engine::ports::ScanRunner;
    #[cfg(feature = "traceroute")]
    use crate::engine::ports::TracerouteRunner;
    use crate::engine::ports::{
        DnsClient, EngineDependencies, EngineOutput, ListenerEventHandler, ListenerRunner,
        PacketPlanner, PacketTransmitter, PortFuture, PreparedDnsQuery, PreparedTrafficRun,
        PrivilegeChecker, RuleActionTelemetry, TargetResolver,
    };

    #[derive(Debug)]
    struct FakePreparedTrafficState {
        plan: Mutex<TrafficPlan>,
        summaries: AtomicUsize,
        executions: AtomicUsize,
    }

    impl FakePreparedTrafficState {
        fn new(plan: TrafficPlan) -> Arc<Self> {
            Arc::new(Self {
                plan: Mutex::new(plan),
                summaries: AtomicUsize::new(0),
                executions: AtomicUsize::new(0),
            })
        }

        fn prepared_run(self: &Arc<Self>) -> PreparedTrafficRun {
            let plan = self.plan.lock().expect("test plan lock").clone();
            let state = Arc::clone(self);
            PreparedTrafficRun::new(
                plan,
                Box::new(move || {
                    Box::pin(async move {
                        state.executions.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })
                }),
            )
        }

        fn summary_count(&self) -> usize {
            self.summaries.load(Ordering::SeqCst)
        }

        fn execution_count(&self) -> usize {
            self.executions.load(Ordering::SeqCst)
        }
    }

    #[derive(Debug)]
    struct FakePreparedTrafficRunner {
        state: Arc<FakePreparedTrafficState>,
    }

    impl FakePreparedTrafficRunner {
        fn new(state: Arc<FakePreparedTrafficState>) -> Self {
            Self { state }
        }
    }

    #[cfg(feature = "traceroute")]
    impl TracerouteRunner for FakePreparedTrafficRunner {
        fn prepare(
            &self,
            _request: TracerouteRequest,
            _policy: TrafficPolicy,
        ) -> PortFuture<PreparedTrafficRun> {
            let state = Arc::clone(&self.state);
            Box::pin(async move { Ok(state.prepared_run()) })
        }
    }

    #[cfg(feature = "scan")]
    impl ScanRunner for FakePreparedTrafficRunner {
        fn prepare(
            &self,
            _request: ScanRequest,
            _policy: TrafficPolicy,
        ) -> PortFuture<PreparedTrafficRun> {
            let state = Arc::clone(&self.state);
            Box::pin(async move { Ok(state.prepared_run()) })
        }
    }

    #[cfg(feature = "fuzz")]
    impl FuzzRunner for FakePreparedTrafficRunner {
        fn prepare(
            &self,
            _request: FuzzRequest,
            _policy: TrafficPolicy,
        ) -> PortFuture<PreparedTrafficRun> {
            let state = Arc::clone(&self.state);
            Box::pin(async move { Ok(state.prepared_run()) })
        }
    }

    #[derive(Debug)]
    struct FakeOutput {
        state: Arc<FakePreparedTrafficState>,
    }

    impl EngineOutput for FakeOutput {
        fn stdout(&self, _bytes: &[u8]) -> crate::engine::ports::PortResult<()> {
            Ok(())
        }

        fn emit_preflight_summary(
            &self,
            _spec: &PacketSpec,
            _plan: &TransmissionPlan,
        ) -> crate::engine::ports::PortResult<()> {
            Ok(())
        }

        fn emit_traffic_plan_summary(
            &self,
            _plan: &TrafficPlan,
        ) -> crate::engine::ports::PortResult<()> {
            self.state.summaries.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn emit_listener_event(&self, _event: &ListenerEvent) {}

        fn emit_dns_dry_run(&self, _request: &DnsRequest) -> crate::engine::ports::PortResult<()> {
            Ok(())
        }

        fn emit_dns_response(
            &self,
            _result: &DnsQueryResult,
        ) -> crate::engine::ports::PortResult<()> {
            Ok(())
        }

        fn format_dns_dry_run(
            &self,
            _request: &DnsRequest,
        ) -> crate::engine::ports::PortResult<String> {
            Ok("dry-run".to_string())
        }

        fn format_dns_response(
            &self,
            _result: &DnsQueryResult,
        ) -> crate::engine::ports::PortResult<String> {
            Ok("response".to_string())
        }
    }

    #[derive(Debug)]
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
            Box::pin(async { Err(anyhow!("privilege checker should not be used")) })
        }
    }

    impl PacketPlanner for UnusedPorts {
        fn plan_packet(
            &self,
            _spec: Arc<PacketSpec>,
            _mode: PlanningMode,
            _policy: crate::domain::policy::TransmissionPolicy,
        ) -> PortFuture<TransmissionPlan> {
            Box::pin(async { Err(anyhow!("packet planner should not be used")) })
        }
    }

    impl PacketTransmitter for UnusedPorts {
        fn transmit(&self, _plan: TransmissionPlan) -> PortFuture<()> {
            Box::pin(async { Err(anyhow!("packet transmitter should not be used")) })
        }
    }

    impl ListenerRunner for UnusedPorts {
        fn run_for_packet(
            &self,
            _spec: ListenerSpec,
            _interface_hint: Option<String>,
            _handler: ListenerEventHandler,
        ) -> PortFuture<()> {
            Box::pin(async { Err(anyhow!("listener runner should not be used")) })
        }

        #[cfg(feature = "pcap")]
        fn run_command(
            &self,
            _request: ListenRequest,
            _handler: ListenerEventHandler,
        ) -> PortFuture<()> {
            Box::pin(async { Err(anyhow!("listener command should not be used")) })
        }
    }

    #[cfg(feature = "daemon")]
    impl DaemonListenerRuntime for UnusedPorts {
        fn validate_options(
            &self,
            _options: &ListenerRequest,
        ) -> crate::engine::ports::PortResult<()> {
            Err(anyhow!("daemon listener validation should not be used"))
        }

        fn spawn_background(
            &self,
            _options: ListenerRequest,
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

    impl DnsClient for UnusedPorts {
        fn prepare(
            &self,
            _request: DnsRequest,
            _policy: TrafficPolicy,
        ) -> PortFuture<PreparedDnsQuery> {
            Box::pin(async { Err(anyhow!("dns client should not be used")) })
        }
    }

    impl RuleActionTelemetry for UnusedPorts {
        fn record_rule_action(&self, _action: &'static str, _status: &'static str) {}

        fn record_rule_executor_drop(&self, _action: &'static str, _reason: &'static str) {}
    }

    fn engine_with_plan(
        mode: TrafficMode,
        scope: TargetScope,
        dry_run: bool,
    ) -> (Engine, Arc<FakePreparedTrafficState>) {
        let state = FakePreparedTrafficState::new(TrafficPlan::new(mode, scope));
        let unused = Arc::new(UnusedPorts);
        let runner = Arc::new(FakePreparedTrafficRunner::new(Arc::clone(&state)));

        let dependencies = EngineDependencies {
            target_resolver: unused.clone(),
            privilege_checker: unused.clone(),
            packet_planner: unused.clone(),
            packet_transmitter: unused.clone(),
            listener_runner: unused.clone(),
            #[cfg(feature = "daemon")]
            daemon_listener_runtime: unused.clone(),
            dns_client: unused.clone(),
            #[cfg(feature = "traceroute")]
            traceroute_runner: runner.clone(),
            #[cfg(feature = "scan")]
            scan_runner: runner.clone(),
            #[cfg(feature = "fuzz")]
            fuzz_runner: runner,
            output: Arc::new(FakeOutput {
                state: Arc::clone(&state),
            }),
            rule_action_telemetry: unused,
        };
        let config = EngineConfig {
            prometheus_bind: None,
            rule_workers: None,
            rule_queue: None,
            send_workers: None,
            send_queue: None,
            traffic_policy: TrafficPolicy::default(),
            dry_run,
        };

        (
            Engine::new_with_optional_runtime_handle(config, dependencies, None).unwrap(),
            state,
        )
    }

    fn assert_counts(state: &FakePreparedTrafficState, summaries: usize, executions: usize) {
        assert_eq!(state.summary_count(), summaries);
        assert_eq!(state.execution_count(), executions);
    }

    #[cfg(feature = "traceroute")]
    fn traceroute_request() -> TracerouteRequest {
        TracerouteRequest {
            destination: "192.0.2.1".to_string(),
            max_ttl: 4,
            probes: 1,
            protocol: TracerouteProtocol::Udp,
            no_dns: Some(true),
            timeout: 100,
        }
    }

    #[cfg(feature = "scan")]
    fn scan_request() -> ScanRequest {
        ScanRequest::TcpSyn(PortScanRequest {
            target: "192.0.2.1".to_string(),
            ports: "80".to_string(),
            interface: None,
            source_ip: None,
        })
    }

    #[cfg(feature = "fuzz")]
    fn fuzz_request() -> FuzzRequest {
        FuzzRequest {
            target: "192.0.2.1".to_string(),
            port: Some(80),
            protocol: FuzzProtocol::Tcp,
            strategy: FuzzStrategy::BitFlip,
            count: 1,
            delay: 0,
        }
    }

    #[cfg(feature = "traceroute")]
    #[tokio::test]
    async fn traceroute_dry_run_emits_summary_without_execution() {
        let (mut engine, state) =
            engine_with_plan(TrafficMode::Traceroute, TargetScope::Private, true);

        engine.run_traceroute(&traceroute_request()).await.unwrap();

        assert_counts(&state, 1, 0);
    }

    #[cfg(feature = "traceroute")]
    #[tokio::test]
    async fn traceroute_live_executes_once_without_summary() {
        let (mut engine, state) =
            engine_with_plan(TrafficMode::Traceroute, TargetScope::Private, false);

        engine.run_traceroute(&traceroute_request()).await.unwrap();

        assert_counts(&state, 0, 1);
    }

    #[cfg(feature = "traceroute")]
    #[tokio::test]
    async fn traceroute_authorization_failure_does_not_execute() {
        let (mut engine, state) =
            engine_with_plan(TrafficMode::Traceroute, TargetScope::Public, false);

        assert!(engine.run_traceroute(&traceroute_request()).await.is_err());

        assert_counts(&state, 0, 0);
    }

    #[cfg(feature = "scan")]
    #[tokio::test]
    async fn scan_dry_run_emits_summary_without_execution() {
        let (mut engine, state) = engine_with_plan(TrafficMode::Scan, TargetScope::Private, true);

        engine.run_scan(&scan_request()).await.unwrap();

        assert_counts(&state, 1, 0);
    }

    #[cfg(feature = "scan")]
    #[tokio::test]
    async fn scan_live_executes_once_without_summary() {
        let (mut engine, state) = engine_with_plan(TrafficMode::Scan, TargetScope::Private, false);

        engine.run_scan(&scan_request()).await.unwrap();

        assert_counts(&state, 0, 1);
    }

    #[cfg(feature = "scan")]
    #[tokio::test]
    async fn scan_authorization_failure_does_not_execute() {
        let (mut engine, state) = engine_with_plan(TrafficMode::Scan, TargetScope::Public, false);

        assert!(engine.run_scan(&scan_request()).await.is_err());

        assert_counts(&state, 0, 0);
    }

    #[cfg(feature = "fuzz")]
    #[tokio::test]
    async fn fuzz_dry_run_emits_summary_without_execution() {
        let (mut engine, state) = engine_with_plan(TrafficMode::Fuzz, TargetScope::Private, true);

        engine.run_fuzz(&fuzz_request()).await.unwrap();

        assert_counts(&state, 1, 0);
    }

    #[cfg(feature = "fuzz")]
    #[tokio::test]
    async fn fuzz_live_executes_once_without_summary() {
        let (mut engine, state) = engine_with_plan(TrafficMode::Fuzz, TargetScope::Private, false);

        engine.run_fuzz(&fuzz_request()).await.unwrap();

        assert_counts(&state, 0, 1);
    }

    #[cfg(feature = "fuzz")]
    #[tokio::test]
    async fn fuzz_authorization_failure_does_not_execute() {
        let (mut engine, state) = engine_with_plan(TrafficMode::Fuzz, TargetScope::Public, false);

        assert!(engine.run_fuzz(&fuzz_request()).await.is_err());

        assert_counts(&state, 0, 0);
    }
}
