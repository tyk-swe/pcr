// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use anyhow::{Context, Result};
use log::debug;

use crate::domain::policy::{
    classify_ip, combine_target_scopes, packet_spec_privileges, packet_spec_target_scope,
    packet_spec_uses_malformed_options, TargetScope, TrafficMode, TrafficPlan, TransmissionPolicy,
};
use crate::domain::request::PacketRequest;
use crate::domain::spec::PacketSpec;
use crate::domain::transmission::{
    emission_accounting, validate_transmission_policy, PlanningMode, TransmissionPlan,
    TransmissionTarget,
};
use crate::engine::error::{EngineError, EngineResult};
use crate::engine::ports::{resolve_packet_request, EngineDependencies};

#[derive(Debug, Clone)]
pub(crate) struct SendUseCase {
    policy: TransmissionPolicy,
    dry_run: bool,
    dependencies: EngineDependencies,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedPacketSend {
    pub plan: TransmissionPlan,
}

impl SendUseCase {
    pub(crate) fn new(policy: TransmissionPolicy, dependencies: EngineDependencies) -> Self {
        Self {
            dry_run: policy.dry_run,
            policy,
            dependencies,
        }
    }

    pub(crate) fn validate_request_policy(&self, request: &PacketRequest) -> EngineResult<()> {
        let plan = TrafficPlan::from_packet_request(request, TrafficMode::Send, &self.policy);
        self.policy
            .authorize(&plan)
            .map(|_| ())
            .map_err(|e| EngineError::TransmissionPlan(e.into()))
    }

    pub(crate) fn validate_spec_policy(&self, spec: &PacketSpec) -> EngineResult<()> {
        validate_transmission_policy(&spec.transmit, self.policy)
            .map_err(|e| EngineError::TransmissionPlan(e.into()))
    }

    pub(crate) async fn check_privileges(&self, spec: Arc<PacketSpec>) -> Result<()> {
        self.dependencies
            .privilege_checker
            .check_packet_send(spec)
            .await
            .map_err(|source| EngineError::InsufficientPrivileges(source).into())
    }

    pub(crate) async fn prepare(
        &self,
        request: PacketRequest,
        check_privileges: bool,
    ) -> Result<PreparedPacketSend> {
        let spec = self.resolve_spec(request).await?;
        self.validate_spec_policy(spec.as_ref())?;

        if self.dry_run {
            let plan = self.plan_dry_run(Arc::clone(&spec)).await?;
            self.authorize_transmission_plan(spec.as_ref(), &plan)?;
            return Ok(PreparedPacketSend { plan });
        }

        self.authorize_spec_traffic(spec.as_ref(), TrafficMode::Send)?;

        if check_privileges {
            self.check_privileges(Arc::clone(&spec)).await?;
        }

        let plan = self.plan_live(Arc::clone(&spec)).await?;
        self.authorize_transmission_plan(spec.as_ref(), &plan)?;
        Ok(PreparedPacketSend { plan })
    }

    #[cfg(feature = "fuzz")]
    pub(crate) async fn execute_generated_fuzz_packet(&self, spec: PacketSpec) -> Result<()> {
        let spec = Arc::new(spec);
        self.validate_spec_policy(spec.as_ref())?;

        if self.dry_run {
            let plan = self.plan_dry_run(Arc::clone(&spec)).await?;
            self.authorize_transmission_plan_for_mode(spec.as_ref(), &plan, TrafficMode::Fuzz)?;
            self.execute_plan(plan).await?;
            return Ok(());
        }

        self.authorize_spec_traffic(spec.as_ref(), TrafficMode::Fuzz)?;
        self.check_privileges(Arc::clone(&spec)).await?;

        let plan = self.plan_live(Arc::clone(&spec)).await?;
        self.authorize_transmission_plan_for_mode(spec.as_ref(), &plan, TrafficMode::Fuzz)?;
        self.execute_plan(plan).await
    }

    pub(crate) async fn resolve_spec(&self, request: PacketRequest) -> Result<Arc<PacketSpec>> {
        self.validate_request_policy(&request)?;
        let request = self.resolve_request(request).await?;
        self.build_spec(request).await
    }

    async fn build_spec(&self, request: PacketRequest) -> Result<Arc<PacketSpec>> {
        let spec = tokio::task::spawn_blocking(move || {
            let spec = PacketSpec::from_request(&request)
                .map_err(|source| EngineError::PacketSpecBuild(source.into()))?;
            debug!("Resolved packet spec: {spec:?}");
            Ok::<_, anyhow::Error>(spec)
        })
        .await
        .context("packet spec task failed")
        .map_err(EngineError::PacketSpecBuild)??;

        Ok(Arc::new(spec))
    }

    async fn resolve_request(&self, request: PacketRequest) -> Result<PacketRequest> {
        resolve_packet_request(request, Arc::clone(&self.dependencies.target_resolver))
            .await
            .map_err(|source| EngineError::PacketSpecBuild(source).into())
    }

    pub(crate) async fn plan_dry_run(&self, spec: Arc<PacketSpec>) -> Result<TransmissionPlan> {
        self.plan_with_mode(spec, true).await
    }

    pub(crate) async fn plan_live(&self, spec: Arc<PacketSpec>) -> Result<TransmissionPlan> {
        self.plan_with_mode(spec, false).await
    }

    async fn plan_with_mode(
        &self,
        spec: Arc<PacketSpec>,
        dry_run: bool,
    ) -> Result<TransmissionPlan> {
        let mode = if dry_run {
            PlanningMode::DryRun
        } else {
            PlanningMode::Live
        };
        let tx_plan = self
            .dependencies
            .packet_planner
            .plan_packet(spec, mode, self.policy)
            .await
            .map_err(|source| anyhow::Error::from(EngineError::TransmissionPlan(source)))?;

        debug!(
            "Transmission plan: transport={} payload={} bytes frames={} largest_frame={} bytes",
            tx_plan.summary.transport,
            tx_plan.summary.payload_len,
            tx_plan.summary.frame_count,
            tx_plan.summary.largest_frame_len
        );
        Ok(tx_plan)
    }

    pub(crate) fn authorize_transmission_plan(
        &self,
        spec: &PacketSpec,
        plan: &TransmissionPlan,
    ) -> EngineResult<TrafficPlan> {
        self.authorize_transmission_plan_for_mode(spec, plan, TrafficMode::Send)
    }

    fn authorize_transmission_plan_for_mode(
        &self,
        spec: &PacketSpec,
        plan: &TransmissionPlan,
        mode: TrafficMode,
    ) -> EngineResult<TrafficPlan> {
        let traffic_plan = self.traffic_plan_from_transmission(spec, plan, mode)?;
        self.policy
            .authorize(&traffic_plan)
            .map_err(|e| EngineError::TransmissionPlan(e.into()))?;
        Ok(traffic_plan)
    }

    pub(crate) fn authorize_spec_traffic(
        &self,
        spec: &PacketSpec,
        mode: TrafficMode,
    ) -> EngineResult<TrafficPlan> {
        let traffic_plan = self.traffic_plan_from_spec(spec, mode)?;
        self.policy
            .authorize(&traffic_plan)
            .map_err(|e| EngineError::TransmissionPlan(e.into()))?;
        Ok(traffic_plan)
    }

    pub(crate) async fn execute_plan(&self, plan: TransmissionPlan) -> Result<()> {
        if self.dry_run {
            log::info!(
                "Dry-run mode: would send {} frame(s) via {} ({} bytes largest)",
                plan.summary.frame_count,
                plan.interface_name,
                plan.summary.largest_frame_len
            );
            return Ok(());
        }

        self.dependencies
            .packet_transmitter
            .transmit(plan)
            .await
            .map_err(|source| anyhow::Error::from(EngineError::TransmissionExecution(source)))?;
        Ok(())
    }

    fn traffic_plan_from_transmission(
        &self,
        spec: &PacketSpec,
        plan: &TransmissionPlan,
        mode: TrafficMode,
    ) -> EngineResult<TrafficPlan> {
        let planned_target_scope = match &plan.destination {
            TransmissionTarget::Ipv4(addr) => classify_ip((*addr).into()),
            TransmissionTarget::Ipv6(addr) => classify_ip((*addr).into()),
        };
        let target_scope =
            combine_target_scopes([planned_target_scope, packet_spec_target_scope(spec)]);

        self.traffic_plan_for_spec_emission(spec, mode, target_scope, plan.frames.len() as u64)
    }

    fn traffic_plan_from_spec(
        &self,
        spec: &PacketSpec,
        mode: TrafficMode,
    ) -> EngineResult<TrafficPlan> {
        self.traffic_plan_for_spec_emission(spec, mode, packet_spec_target_scope(spec), 1)
    }

    fn traffic_plan_for_spec_emission(
        &self,
        spec: &PacketSpec,
        mode: TrafficMode,
        target_scope: TargetScope,
        units_per_attempt: u64,
    ) -> EngineResult<TrafficPlan> {
        let accounting = emission_accounting(&spec.transmit, self.policy, units_per_attempt)
            .map_err(|e| EngineError::TransmissionPlan(e.into()))?;
        let unbounded = accounting.attempts.is_none();
        let estimated_packets = accounting.total_emitted_units;

        let mut traffic_plan = TrafficPlan::with_shape(
            mode,
            target_scope,
            1,
            1,
            estimated_packets,
            units_per_attempt.min(usize::MAX as u64) as usize,
            Some(self.policy.budget.max_rate_per_sec),
        );
        traffic_plan.malformed = packet_spec_uses_malformed_options(spec);
        traffic_plan.unbounded = unbounded;
        traffic_plan.required_privileges = packet_spec_privileges(spec);
        Ok(traffic_plan)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::domain::request::{DestinationRequest, PacketRequest};
    use crate::engine::ports::{
        EngineDependencies, PacketPlanner, PacketTransmitter, PortFuture, PrivilegeChecker,
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
        ipv4_udp_transmission_plan, NoOpOutput, NoOpRuleActionTelemetry, RejectDnsClient,
        RejectListenerRunner, RejectPacketPlanner, RejectTargetResolver,
    };

    #[derive(Default)]
    struct SharedState {
        events: Mutex<Vec<&'static str>>,
        planned_modes: Mutex<Vec<PlanningMode>>,
        transmit_calls: AtomicUsize,
    }

    impl SharedState {
        fn record(&self, event: &'static str) {
            self.events.lock().expect("test events lock").push(event);
        }

        fn events(&self) -> Vec<&'static str> {
            self.events.lock().expect("test events lock").clone()
        }

        fn record_mode(&self, mode: PlanningMode) {
            self.planned_modes
                .lock()
                .expect("test modes lock")
                .push(mode);
        }

        fn planned_modes(&self) -> Vec<PlanningMode> {
            self.planned_modes.lock().expect("test modes lock").clone()
        }
    }

    struct RecordingPrivilegeChecker {
        state: Arc<SharedState>,
    }

    impl PrivilegeChecker for RecordingPrivilegeChecker {
        fn check_packet_send(&self, _spec: Arc<PacketSpec>) -> PortFuture<()> {
            let state = Arc::clone(&self.state);
            Box::pin(async move {
                state.record("privilege");
                Ok(())
            })
        }
    }

    struct RecordingPacketPlanner {
        state: Arc<SharedState>,
    }

    impl PacketPlanner for RecordingPacketPlanner {
        fn plan_packet(
            &self,
            _spec: Arc<PacketSpec>,
            mode: PlanningMode,
            _policy: crate::domain::policy::TransmissionPolicy,
        ) -> PortFuture<TransmissionPlan> {
            let state = Arc::clone(&self.state);
            Box::pin(async move {
                state.record("plan");
                state.record_mode(mode);
                Ok(ipv4_udp_transmission_plan(mode))
            })
        }
    }

    struct RecordingPacketTransmitter {
        state: Arc<SharedState>,
    }

    impl PacketTransmitter for RecordingPacketTransmitter {
        fn transmit(&self, _plan: TransmissionPlan) -> PortFuture<()> {
            let state = Arc::clone(&self.state);
            Box::pin(async move {
                state.transmit_calls.fetch_add(1, Ordering::SeqCst);
                state.record("transmit");
                Ok(())
            })
        }
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

    fn send_use_case(
        dry_run: bool,
        privilege_checker: Arc<dyn PrivilegeChecker>,
        packet_planner: Arc<dyn PacketPlanner>,
        packet_transmitter: Arc<dyn PacketTransmitter>,
    ) -> SendUseCase {
        SendUseCase::new(
            crate::domain::policy::TrafficPolicy::default().with_dry_run(dry_run),
            EngineDependencies {
                target_resolver: Arc::new(RejectTargetResolver),
                privilege_checker,
                packet_planner,
                packet_transmitter,
                listener_runner: Arc::new(RejectListenerRunner),
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
            },
        )
    }

    #[tokio::test]
    async fn prepare_dry_run_uses_dry_run_planning_and_skips_privilege_checks() {
        let state = Arc::new(SharedState::default());
        let send = send_use_case(
            true,
            Arc::new(RecordingPrivilegeChecker {
                state: Arc::clone(&state),
            }),
            Arc::new(RecordingPacketPlanner {
                state: Arc::clone(&state),
            }),
            Arc::new(RecordingPacketTransmitter {
                state: Arc::clone(&state),
            }),
        );

        let prepared = send.prepare(request(), true).await.unwrap();

        assert_eq!(state.planned_modes(), vec![PlanningMode::DryRun]);
        assert_eq!(state.events(), vec!["plan"]);
        assert_eq!(prepared.plan.mode, PlanningMode::DryRun);
    }

    #[tokio::test]
    async fn prepare_live_uses_live_planning_and_checks_privileges_before_planning() {
        let state = Arc::new(SharedState::default());
        let send = send_use_case(
            false,
            Arc::new(RecordingPrivilegeChecker {
                state: Arc::clone(&state),
            }),
            Arc::new(RecordingPacketPlanner {
                state: Arc::clone(&state),
            }),
            Arc::new(RecordingPacketTransmitter {
                state: Arc::clone(&state),
            }),
        );

        let prepared = send.prepare(request(), true).await.unwrap();

        assert_eq!(state.planned_modes(), vec![PlanningMode::Live]);
        assert_eq!(state.events(), vec!["privilege", "plan"]);
        assert_eq!(prepared.plan.mode, PlanningMode::Live);
    }

    #[tokio::test]
    async fn execute_plan_dry_run_returns_without_calling_packet_transmitter() {
        let state = Arc::new(SharedState::default());
        let send = send_use_case(
            true,
            Arc::new(RecordingPrivilegeChecker {
                state: Arc::clone(&state),
            }),
            Arc::new(RejectPacketPlanner),
            Arc::new(RecordingPacketTransmitter {
                state: Arc::clone(&state),
            }),
        );

        send.execute_plan(ipv4_udp_transmission_plan(PlanningMode::DryRun))
            .await
            .unwrap();

        assert_eq!(state.transmit_calls.load(Ordering::SeqCst), 0);
        assert!(state.events().is_empty());
    }
}
