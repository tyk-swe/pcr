// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use anyhow::{Context, Result};
use log::debug;

use crate::domain::policy::{
    classify_ip, combine_target_scopes, packet_spec_privileges, packet_spec_target_scope,
    packet_spec_uses_malformed_options, TrafficMode, TrafficPlan, TransmissionPolicy,
};
use crate::domain::request::PacketRequest;
use crate::domain::spec::{PacketSpec, TransportSpec};
use crate::engine::config::EngineConfig;
use crate::engine::error::{EngineError, EngineResult};
use crate::engine::resolve::{resolve_packet_request, SystemTargetResolver};
use crate::network::io::sender::{
    emission_accounting, validate_transmission_policy, NetworkTarget, TransmissionPlan,
};

#[derive(Debug, Clone)]
pub struct PacketSendService {
    policy: TransmissionPolicy,
    dry_run: bool,
}

#[derive(Debug, Clone)]
pub struct PreparedPacketSend {
    pub spec: Arc<PacketSpec>,
    pub plan: TransmissionPlan,
}

impl PacketSendService {
    pub fn from_config(config: &EngineConfig) -> Self {
        Self::new(config.traffic_policy.with_dry_run(config.dry_run))
    }

    pub fn new(policy: TransmissionPolicy) -> Self {
        Self {
            dry_run: policy.dry_run,
            policy,
        }
    }

    pub fn validate_request_policy(&self, request: &PacketRequest) -> EngineResult<()> {
        let plan = TrafficPlan::from_packet_request(request, TrafficMode::Send, &self.policy);
        self.policy
            .authorize(&plan)
            .map(|_| ())
            .map_err(|e| EngineError::TransmissionPlan(e.into()))
    }

    pub fn validate_spec_policy(&self, spec: &PacketSpec) -> EngineResult<()> {
        validate_transmission_policy(&spec.transmit, self.policy)
            .map_err(|e| EngineError::TransmissionPlan(e.into()))
    }

    pub async fn prepare(
        &self,
        request: PacketRequest,
        check_privileges: bool,
    ) -> Result<PreparedPacketSend> {
        let spec = self.resolve_spec(request).await?;
        self.validate_spec_policy(spec.as_ref())?;

        if self.dry_run {
            let plan = self.plan_dry_run(Arc::clone(&spec)).await?;
            self.authorize_transmission_plan(spec.as_ref(), &plan)?;
            return Ok(PreparedPacketSend { spec, plan });
        }

        self.authorize_spec_traffic(spec.as_ref(), TrafficMode::Send)?;

        if check_privileges {
            let spec_for_check = Arc::clone(&spec);
            tokio::task::spawn_blocking(move || Self::check_privileges(spec_for_check.as_ref()))
                .await
                .context("privilege check task failed")??;
        }

        let plan = self.plan_live(Arc::clone(&spec)).await?;
        self.authorize_transmission_plan(spec.as_ref(), &plan)?;
        Ok(PreparedPacketSend { spec, plan })
    }

    pub async fn resolve_spec(&self, request: PacketRequest) -> Result<Arc<PacketSpec>> {
        self.validate_request_policy(&request)?;
        self.build_spec(request).await
    }

    async fn build_spec(&self, request: PacketRequest) -> Result<Arc<PacketSpec>> {
        let spec = tokio::task::spawn_blocking(move || {
            let request = resolve_packet_request(request, &SystemTargetResolver)
                .map_err(|source| EngineError::PacketSpecBuild(source.into()))?;
            let spec = PacketSpec::from_request(&request)
                .map_err(|source| EngineError::PacketSpecBuild(source.into()))?;
            debug!("Resolved packet spec: {spec:?}");
            Ok::<_, anyhow::Error>(spec)
        })
        .await
        .context("packet spec task failed")??;

        Ok(Arc::new(spec))
    }

    pub async fn plan(&self, spec: Arc<PacketSpec>) -> Result<TransmissionPlan> {
        if self.dry_run {
            self.plan_dry_run(spec).await
        } else {
            self.plan_live(spec).await
        }
    }

    pub async fn plan_dry_run(&self, spec: Arc<PacketSpec>) -> Result<TransmissionPlan> {
        self.plan_with_mode(spec, true).await
    }

    pub async fn plan_live(&self, spec: Arc<PacketSpec>) -> Result<TransmissionPlan> {
        self.plan_with_mode(spec, false).await
    }

    async fn plan_with_mode(
        &self,
        spec: Arc<PacketSpec>,
        dry_run: bool,
    ) -> Result<TransmissionPlan> {
        let policy = self.policy;
        let tx_plan = tokio::task::spawn_blocking(move || {
            if dry_run {
                crate::network::io::sender::plan_transmission_dry_run_with_policy(
                    spec.as_ref(),
                    policy,
                )
            } else {
                crate::network::io::sender::plan_transmission_with_policy(spec.as_ref(), policy)
            }
            .map_err(|e| EngineError::TransmissionPlan(e.into()))
        })
        .await
        .context("transmission planning task failed")??;

        debug!(
            "Transmission plan: transport={} payload={} bytes frames={} largest_frame={} bytes",
            tx_plan.summary.transport,
            tx_plan.summary.payload_len,
            tx_plan.summary.frame_count,
            tx_plan.summary.largest_frame_len
        );
        Ok(tx_plan)
    }

    pub fn authorize_transmission_plan(
        &self,
        spec: &PacketSpec,
        plan: &TransmissionPlan,
    ) -> EngineResult<TrafficPlan> {
        let traffic_plan = self.traffic_plan_from_transmission(spec, plan)?;
        self.policy
            .authorize(&traffic_plan)
            .map_err(|e| EngineError::TransmissionPlan(e.into()))?;
        Ok(traffic_plan)
    }

    pub fn authorize_spec_traffic(
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

    pub async fn execute_plan(&self, plan: TransmissionPlan) -> Result<()> {
        if self.dry_run {
            log::info!(
                "Dry-run mode: would send {} frame(s) via {} ({} bytes largest)",
                plan.summary.frame_count,
                plan.interface.name,
                plan.summary.largest_frame_len
            );
            return Ok(());
        }

        crate::network::io::sender::emit_metrics_snapshot(&plan)
            .map_err(|e| EngineError::TransmissionPlan(e.into()))?;
        crate::network::io::sender::execute_transmission(plan)
            .await
            .map_err(|e| EngineError::TransmissionExecution(e.into()))?;
        Ok(())
    }

    pub fn check_privileges(spec: &PacketSpec) -> EngineResult<()> {
        let requires_raw = spec.layer2.source.is_some()
            || spec.layer2.destination.is_some()
            || matches!(
                &spec.transport,
                TransportSpec::Tcp(_)
                    | TransportSpec::Udp(_)
                    | TransportSpec::Icmp(_)
                    | TransportSpec::Icmpv6(_)
            )
            || spec.transmit.is_layer3();

        if requires_raw {
            crate::util::privileges::assert_raw_socket_capability()
                .map_err(|e| EngineError::InsufficientPrivileges(e.into()))?;
        }
        Ok(())
    }

    fn traffic_plan_from_transmission(
        &self,
        spec: &PacketSpec,
        plan: &TransmissionPlan,
    ) -> EngineResult<TrafficPlan> {
        let accounting = emission_accounting(&spec.transmit, self.policy, plan.frames.len() as u64)
            .map_err(|e| EngineError::TransmissionPlan(e.into()))?;
        let unbounded = accounting.attempts.is_none();
        let estimated_packets = accounting.total_emitted_units;
        let planned_target_scope = match &plan.destination {
            NetworkTarget::Ipv4(addr) => classify_ip((*addr).into()),
            NetworkTarget::Ipv6(addr) => classify_ip((*addr).into()),
        };
        let target_scope =
            combine_target_scopes([planned_target_scope, packet_spec_target_scope(spec)]);

        let mut traffic_plan = TrafficPlan::new(TrafficMode::Send, target_scope);
        traffic_plan.target_count = 1;
        traffic_plan.port_count = 1;
        traffic_plan.estimated_packets = estimated_packets;
        traffic_plan.malformed = packet_spec_uses_malformed_options(spec);
        traffic_plan.unbounded = unbounded;
        traffic_plan.batch_size = plan.frames.len().max(1);
        traffic_plan.rate_per_sec = Some(self.policy.budget.max_rate_per_sec);
        traffic_plan.required_privileges = packet_spec_privileges(spec);

        Ok(traffic_plan)
    }

    fn traffic_plan_from_spec(
        &self,
        spec: &PacketSpec,
        mode: TrafficMode,
    ) -> EngineResult<TrafficPlan> {
        let accounting = emission_accounting(&spec.transmit, self.policy, 1)
            .map_err(|e| EngineError::TransmissionPlan(e.into()))?;
        let unbounded = accounting.attempts.is_none();
        let estimated_packets = accounting.total_emitted_units;

        let mut traffic_plan = TrafficPlan::new(mode, packet_spec_target_scope(spec));
        traffic_plan.target_count = 1;
        traffic_plan.port_count = 1;
        traffic_plan.estimated_packets = estimated_packets;
        traffic_plan.malformed = packet_spec_uses_malformed_options(spec);
        traffic_plan.unbounded = unbounded;
        traffic_plan.batch_size = 1;
        traffic_plan.rate_per_sec = Some(self.policy.budget.max_rate_per_sec);
        traffic_plan.required_privileges = packet_spec_privileges(spec);
        Ok(traffic_plan)
    }
}
