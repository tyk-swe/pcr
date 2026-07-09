// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::{Context, Result};
#[cfg(feature = "pcap")]
use log::warn;
use log::{debug, info};
#[cfg(feature = "pcap")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(feature = "pcap")]
use std::time::Duration;

use crate::domain::policy::TrafficMode;
use crate::domain::request::PacketRequest;
use crate::domain::spec::PacketSpec;
use crate::domain::transmission::TransmissionPlan;
use crate::engine::core::Engine;
use crate::engine::error::{EngineError, EngineResult};

#[cfg(feature = "pcap")]
const LISTENER_STARTUP_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) struct OneShotFlow<'engine> {
    engine: &'engine mut Engine,
    request: PacketRequest,
    spec: Option<std::sync::Arc<PacketSpec>>,
    plan: Option<TransmissionPlan>,
}

impl<'engine> OneShotFlow<'engine> {
    pub(crate) fn new(engine: &'engine mut Engine, request: PacketRequest) -> Self {
        Self {
            engine,
            request,
            spec: None,
            plan: None,
        }
    }

    pub(crate) async fn with_spec(mut self) -> Result<Self> {
        self.log_one_shot_entry();
        let request = self.request.clone();
        let spec = self.engine.send.resolve_spec(request).await?;
        self.announce_listener(spec.as_ref());
        self.spec = Some(spec);
        Ok(self)
    }

    pub(crate) fn with_policy_validation(self) -> Result<Self> {
        self.engine.send.validate_request_policy(&self.request)?;
        Ok(self)
    }

    pub(crate) async fn with_rules(self) -> Result<Self> {
        if let Some(rules_file) = self.spec()?.rules_file.clone() {
            let path = rules_file.clone();
            let load_path = path.clone();
            let rules = tokio::task::spawn_blocking(move || {
                crate::rules::RuleEngine::load_rules_from_path(&load_path).map_err(|e| {
                    EngineError::rule_load(load_path.to_string_lossy().into_owned(), e.into())
                })
            })
            .await
            .context("rule loading task failed")
            .map_err(|source| {
                EngineError::rule_load(path.to_string_lossy().into_owned(), source)
            })??;

            self.engine.rules.replace_rules(rules);
        }
        Ok(self)
    }

    pub(crate) fn with_startup_rules(self) -> Self {
        if self.engine.rules.has_startup_triggers() && !self.engine.config.dry_run {
            self.engine.rules.run_startup_actions();
        }
        self
    }

    pub(crate) async fn with_authorized_preflight_traffic(mut self) -> Result<Self> {
        let spec = Arc::clone(
            self.spec
                .as_ref()
                .context("packet spec missing; ensure with_spec() is called first")?,
        );
        if !self.engine.config.dry_run {
            self.engine
                .send
                .authorize_spec_traffic(spec.as_ref(), TrafficMode::Send)?;
            return Ok(self);
        }

        let plan = self.engine.send.plan_dry_run(Arc::clone(&spec)).await?;
        self.engine
            .send
            .authorize_transmission_plan(spec.as_ref(), &plan)?;
        self.plan = Some(plan);
        Ok(self)
    }

    pub(crate) async fn with_preflight(self) -> Result<Self> {
        let spec = Arc::clone(
            self.spec
                .as_ref()
                .context("packet spec missing; ensure with_spec() is called first")?,
        );
        self.engine.send.validate_spec_policy(spec.as_ref())?;

        if !self.engine.config.dry_run {
            self.engine.send.check_privileges(spec).await?;
        }

        Ok(self)
    }

    pub(crate) async fn with_plan(mut self) -> Result<Self> {
        if self.engine.config.dry_run {
            return Ok(self);
        }

        let spec = Arc::clone(
            self.spec
                .as_ref()
                .context("packet spec missing; ensure with_spec() is called first")?,
        );
        let plan = self.engine.send.plan_live(Arc::clone(&spec)).await?;
        self.engine
            .send
            .authorize_transmission_plan(spec.as_ref(), &plan)?;
        self.plan = Some(plan);
        Ok(self)
    }

    pub(crate) fn with_preflight_output(self) -> Result<Self> {
        let spec = self.spec()?;
        let plan = self.plan()?;
        self.emit_preflight_summary(spec, plan)?;
        Ok(self)
    }

    pub(crate) async fn execute(mut self) -> Result<()> {
        let spec = self.take_spec()?;
        let plan = self.take_plan()?;

        if self.engine.config.dry_run {
            self.engine.send.execute_plan(plan).await?;
            return Ok(());
        }

        self.execute_live_plan_with_optional_listener(spec.as_ref(), plan)
            .await
    }

    fn spec(&self) -> Result<&PacketSpec> {
        self.spec
            .as_deref()
            .context("packet spec missing; ensure with_spec() is called first")
    }

    fn take_spec(&mut self) -> Result<std::sync::Arc<PacketSpec>> {
        self.spec
            .take()
            .context("packet spec missing during execution; did with_spec() run?")
    }

    fn take_plan(&mut self) -> Result<TransmissionPlan> {
        self.plan
            .take()
            .context("transmission plan missing; ensure with_plan() is called")
    }

    fn plan(&self) -> Result<&TransmissionPlan> {
        self.plan
            .as_ref()
            .context("transmission plan missing; ensure with_plan() is called")
    }

    fn log_one_shot_entry(&self) {
        info!("Executing one-shot mode");
        debug!(
            "Layer2={:?} IP={:?} Transport={:?} Payload={:?} Tx={:?}",
            self.request.layer2,
            self.request.ip,
            self.request.transport,
            self.request.payload,
            self.request.transmit
        );
    }

    fn announce_listener(&self, spec: &PacketSpec) {
        if spec.listener.enabled && spec.listener.implicit {
            info!("Listener auto-enabled to honor reply previews or capture output");
        }
    }

    fn emit_preflight_summary(
        &self,
        spec: &PacketSpec,
        plan: &TransmissionPlan,
    ) -> EngineResult<()> {
        self.engine
            .dependencies
            .output
            .emit_preflight_summary(spec, plan)
            .map_err(EngineError::PreflightSummary)
    }

    #[cfg(not(feature = "pcap"))]
    async fn execute_live_plan_with_optional_listener(
        &mut self,
        _spec: &PacketSpec,
        plan: TransmissionPlan,
    ) -> Result<()> {
        self.engine.send.execute_plan(plan).await
    }

    #[cfg(feature = "pcap")]
    async fn execute_live_plan_with_optional_listener(
        &mut self,
        spec: &PacketSpec,
        plan: TransmissionPlan,
    ) -> Result<()> {
        let listener = self.start_listener(spec).await?;
        let send_result = self.engine.send.execute_plan(plan).await;

        if let Some(listener) = listener {
            listener.shutdown.store(false, Ordering::SeqCst);
            if let Err(listener_err) = self.wait_for_listener(listener).await {
                if send_result.is_err() {
                    warn!("listener shutdown failed after send error: {listener_err:#}");
                } else {
                    return Err(listener_err);
                }
            }
        }

        send_result
    }

    #[cfg(feature = "pcap")]
    async fn start_listener(&self, spec: &PacketSpec) -> Result<Option<ArmedListener>> {
        if !spec.listener.enabled {
            return Ok(None);
        }

        let shutdown = Arc::new(AtomicBool::new(true));
        let listener_shutdown = Arc::clone(&shutdown);
        let (startup_tx, startup_rx) = tokio::sync::oneshot::channel();
        let listener = ArmedListener {
            shutdown,
            task: tokio::spawn(
                self.engine
                    .dependencies
                    .listener_runner
                    .run_for_packet_with_lifecycle(
                        spec.listener.clone(),
                        spec.target.interface.clone(),
                        self.engine.listener_handler(),
                        listener_shutdown,
                        Some(startup_tx),
                    ),
            ),
        };

        match tokio::time::timeout(LISTENER_STARTUP_TIMEOUT, startup_rx).await {
            Ok(Ok(Ok(()))) => Ok(Some(listener)),
            Ok(Ok(Err(message))) => {
                listener.shutdown.store(false, Ordering::SeqCst);
                match self.wait_for_listener(listener).await {
                    Ok(()) => Err(anyhow::Error::from(EngineError::Listener(anyhow::anyhow!(
                        message,
                    )))),
                    Err(err) => Err(err),
                }
            }
            Ok(Err(_)) => {
                listener.shutdown.store(false, Ordering::SeqCst);
                match self.wait_for_listener(listener).await {
                    Ok(()) => Err(anyhow::Error::from(EngineError::Listener(anyhow::anyhow!(
                        "listener task exited before reporting readiness"
                    )))),
                    Err(err) => Err(err),
                }
            }
            Err(_) => {
                listener.shutdown.store(false, Ordering::SeqCst);
                match self.wait_for_listener(listener).await {
                    Ok(()) => Err(anyhow::Error::from(EngineError::Listener(anyhow::anyhow!(
                        "listener startup acknowledgement timed out"
                    )))),
                    Err(err) => Err(err),
                }
            }
        }
    }

    #[cfg(feature = "pcap")]
    async fn wait_for_listener(&self, listener: ArmedListener) -> Result<()> {
        match listener.task.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(source)) => Err(anyhow::Error::from(EngineError::Listener(source))),
            Err(source) => Err(anyhow::Error::from(EngineError::Listener(
                anyhow::Error::new(source),
            ))),
        }
    }
}

#[cfg(feature = "pcap")]
struct ArmedListener {
    shutdown: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<crate::engine::ports::PortResult<()>>,
}

#[cfg(all(test, feature = "pcap"))]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use anyhow::anyhow;
    use tokio::runtime::Handle;
    use tokio::sync::Notify;

    use super::*;
    use crate::domain::policy::TrafficPolicy;
    use crate::domain::request::{DestinationRequest, ListenerRequest};
    use crate::domain::spec::{ListenerSpec, PacketSpec};
    use crate::domain::transmission::{PlanningMode, TransmissionPlan};
    use crate::engine::ports::{
        EngineDependencies, ListenerEventHandler, ListenerRunner, PacketPlanner, PacketTransmitter,
        PortFuture,
    };
    #[cfg(feature = "daemon")]
    use crate::engine::test_support::RejectDaemonListenerRuntime;
    #[cfg(feature = "fuzz")]
    use crate::engine::test_support::RejectFuzzRunner;
    #[cfg(feature = "scan")]
    use crate::engine::test_support::RejectScanRunner;
    #[cfg(feature = "traceroute")]
    use crate::engine::test_support::RejectTracerouteRunner;
    use crate::engine::test_support::{
        ipv4_udp_transmission_plan, AllowPrivilegeChecker, NoOpOutput, NoOpRuleActionTelemetry,
        RejectDnsClient, RejectTargetResolver,
    };
    use crate::engine::{config::EngineConfig, core::Engine};

    #[derive(Clone, Copy)]
    enum ListenerMode {
        ReadyUntilSend,
        FailStartup,
        ReadyUntilShutdown,
    }

    #[derive(Clone, Copy)]
    enum TransmitMode {
        Succeed,
        Fail,
    }

    #[derive(Default)]
    struct SharedState {
        events: Mutex<Vec<&'static str>>,
        send_calls: AtomicUsize,
        send_finished: AtomicBool,
        send_signal: Notify,
    }

    impl SharedState {
        fn record(&self, event: &'static str) {
            self.events.lock().unwrap().push(event);
        }

        fn events(&self) -> Vec<&'static str> {
            self.events.lock().unwrap().clone()
        }
    }

    struct FakePacketPlanner;

    impl PacketPlanner for FakePacketPlanner {
        fn plan_packet(
            &self,
            _spec: Arc<PacketSpec>,
            _mode: PlanningMode,
            _policy: crate::domain::policy::TransmissionPolicy,
        ) -> PortFuture<TransmissionPlan> {
            Box::pin(async { Ok(ipv4_udp_transmission_plan(PlanningMode::Live)) })
        }
    }

    struct FakePacketTransmitter {
        state: Arc<SharedState>,
        mode: TransmitMode,
    }

    impl PacketTransmitter for FakePacketTransmitter {
        fn transmit(&self, _plan: TransmissionPlan) -> PortFuture<()> {
            let state = Arc::clone(&self.state);
            let mode = self.mode;
            Box::pin(async move {
                state.send_calls.fetch_add(1, Ordering::SeqCst);
                state.record("send");
                state.send_finished.store(true, Ordering::SeqCst);
                state.send_signal.notify_waiters();
                match mode {
                    TransmitMode::Succeed => Ok(()),
                    TransmitMode::Fail => Err(anyhow!("send failed")),
                }
            })
        }
    }

    struct FakeListenerRunner {
        state: Arc<SharedState>,
        mode: ListenerMode,
    }

    impl ListenerRunner for FakeListenerRunner {
        #[cfg(not(feature = "pcap"))]
        fn run_for_packet(
            &self,
            _spec: ListenerSpec,
            _interface_hint: Option<String>,
            _handler: ListenerEventHandler,
        ) -> PortFuture<()> {
            Box::pin(async { Err(anyhow!("unexpected non-lifecycle listener path")) })
        }

        fn run_for_packet_with_lifecycle(
            &self,
            _spec: ListenerSpec,
            _interface_hint: Option<String>,
            _handler: ListenerEventHandler,
            shutdown: Arc<AtomicBool>,
            startup: Option<crate::engine::ports::ListenerStartupSignal>,
        ) -> PortFuture<()> {
            let state = Arc::clone(&self.state);
            let mode = self.mode;
            Box::pin(async move {
                state.record("listener_start");
                match mode {
                    ListenerMode::FailStartup => {
                        if let Some(startup) = startup {
                            let _ = startup.send(Err("listener startup failed".to_string()));
                        }
                        Err(anyhow!("listener startup failed"))
                    }
                    ListenerMode::ReadyUntilSend => {
                        if let Some(startup) = startup {
                            let _ = startup.send(Ok(()));
                        }
                        while !state.send_finished.load(Ordering::SeqCst) {
                            state.send_signal.notified().await;
                        }
                        state.record("listener_finish");
                        Ok(())
                    }
                    ListenerMode::ReadyUntilShutdown => {
                        if let Some(startup) = startup {
                            let _ = startup.send(Ok(()));
                        }
                        while shutdown.load(Ordering::SeqCst) {
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                        state.record("listener_finish");
                        Ok(())
                    }
                }
            })
        }

        fn run_command(
            &self,
            _request: crate::domain::command::ListenRequest,
            _handler: ListenerEventHandler,
        ) -> PortFuture<()> {
            Box::pin(async { Err(anyhow!("unexpected listener command path")) })
        }
    }

    fn request() -> PacketRequest {
        PacketRequest {
            destination: DestinationRequest {
                destination_ip: Some("192.0.2.10".to_string()),
                ..Default::default()
            },
            listener: ListenerRequest {
                listen: Some(true),
                timeout: Some(1),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn engine(
        listener_mode: ListenerMode,
        transmit_mode: TransmitMode,
        state: Arc<SharedState>,
    ) -> Engine {
        let transmitter_state = Arc::clone(&state);
        let listener_state = Arc::clone(&state);
        let dependencies = EngineDependencies {
            target_resolver: Arc::new(RejectTargetResolver),
            privilege_checker: Arc::new(AllowPrivilegeChecker),
            packet_planner: Arc::new(FakePacketPlanner),
            packet_transmitter: Arc::new(FakePacketTransmitter {
                state: transmitter_state,
                mode: transmit_mode,
            }),
            listener_runner: Arc::new(FakeListenerRunner {
                state: listener_state,
                mode: listener_mode,
            }),
            #[cfg(feature = "daemon")]
            daemon_listener_runtime: Arc::new(RejectDaemonListenerRuntime),
            dns_client: Arc::new(RejectDnsClient),
            #[cfg(feature = "traceroute")]
            traceroute_runner: Arc::new(RejectTracerouteRunner),
            #[cfg(feature = "scan")]
            scan_runner: Arc::new(RejectScanRunner),
            #[cfg(feature = "fuzz")]
            fuzz_runner: Arc::new(RejectFuzzRunner),
            output: Arc::new(NoOpOutput),
            rule_action_telemetry: Arc::new(NoOpRuleActionTelemetry),
        };
        let config = EngineConfig {
            prometheus_bind: None,
            rule_workers: None,
            rule_queue: None,
            send_workers: None,
            send_queue: None,
            traffic_policy: TrafficPolicy::default(),
            dry_run: false,
        };

        Engine::new_with_runtime_handle(config, dependencies, Handle::current()).unwrap()
    }

    fn error_chain_contains(err: &anyhow::Error, needle: &str) -> bool {
        err.chain().any(|cause| cause.to_string().contains(needle))
    }

    #[tokio::test]
    async fn one_shot_listener_starts_before_send() {
        let state = Arc::new(SharedState::default());
        let mut engine = engine(
            ListenerMode::ReadyUntilSend,
            TransmitMode::Succeed,
            Arc::clone(&state),
        );

        OneShotFlow::new(&mut engine, request())
            .with_policy_validation()
            .unwrap()
            .with_spec()
            .await
            .unwrap()
            .with_authorized_preflight_traffic()
            .await
            .unwrap()
            .with_preflight()
            .await
            .unwrap()
            .with_plan()
            .await
            .unwrap()
            .with_preflight_output()
            .unwrap()
            .execute()
            .await
            .unwrap();

        assert_eq!(
            state.events(),
            ["listener_start", "send", "listener_finish"]
        );
    }

    #[tokio::test]
    async fn one_shot_listener_startup_failure_prevents_send() {
        let state = Arc::new(SharedState::default());
        let mut engine = engine(
            ListenerMode::FailStartup,
            TransmitMode::Succeed,
            Arc::clone(&state),
        );

        let err = OneShotFlow::new(&mut engine, request())
            .with_policy_validation()
            .unwrap()
            .with_spec()
            .await
            .unwrap()
            .with_authorized_preflight_traffic()
            .await
            .unwrap()
            .with_preflight()
            .await
            .unwrap()
            .with_plan()
            .await
            .unwrap()
            .with_preflight_output()
            .unwrap()
            .execute()
            .await
            .unwrap_err();

        assert!(error_chain_contains(&err, "listener startup failed"));
        assert_eq!(state.send_calls.load(Ordering::SeqCst), 0);
        assert_eq!(state.events(), ["listener_start"]);
    }

    #[tokio::test]
    async fn execute_stops_listener_when_send_fails() {
        let state = Arc::new(SharedState::default());
        let mut engine = engine(
            ListenerMode::ReadyUntilShutdown,
            TransmitMode::Fail,
            Arc::clone(&state),
        );

        let err = OneShotFlow::new(&mut engine, request())
            .with_policy_validation()
            .unwrap()
            .with_spec()
            .await
            .unwrap()
            .with_authorized_preflight_traffic()
            .await
            .unwrap()
            .with_preflight()
            .await
            .unwrap()
            .with_plan()
            .await
            .unwrap()
            .with_preflight_output()
            .unwrap()
            .execute()
            .await
            .unwrap_err();

        assert!(error_chain_contains(&err, "send failed"));
        assert_eq!(state.send_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            state.events(),
            ["listener_start", "send", "listener_finish"]
        );
    }
}
