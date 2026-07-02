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
        .context("packet spec task failed")??;

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
            .await?;

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

        self.dependencies.packet_transmitter.transmit(plan).await?;
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

        let mut traffic_plan = TrafficPlan::new(mode, target_scope);
        traffic_plan.target_count = 1;
        traffic_plan.port_count = 1;
        traffic_plan.estimated_packets = estimated_packets;
        traffic_plan.malformed = packet_spec_uses_malformed_options(spec);
        traffic_plan.unbounded = unbounded;
        traffic_plan.batch_size = units_per_attempt.min(usize::MAX as u64) as usize;
        traffic_plan.batch_size = traffic_plan.batch_size.max(1);
        traffic_plan.rate_per_sec = Some(self.policy.budget.max_rate_per_sec);
        traffic_plan.required_privileges = packet_spec_privileges(spec);
        Ok(traffic_plan)
    }
}
