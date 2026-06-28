use std::sync::Arc;

use anyhow::{Context, Result};
use log::debug;

use crate::engine::policy::{
    validate_transmission_policy, validate_unbounded_request_policy, TransmissionPolicy,
};
use crate::engine::request::PacketRequest;
use crate::engine::resolve::{resolve_packet_request, SystemTargetResolver};
use crate::engine::spec::{PacketSpec, TransportSpec};
use crate::engine::{EngineConfig, EngineError, EngineResult};
use crate::network::io::sender::TransmissionPlan;

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
        Self::new(TransmissionPolicy::new(
            config.allow_unbounded_sends,
            config.dry_run,
        ))
    }

    pub fn new(policy: TransmissionPolicy) -> Self {
        Self {
            dry_run: policy.dry_run,
            policy,
        }
    }

    pub fn validate_request_policy(&self, request: &PacketRequest) -> EngineResult<()> {
        validate_unbounded_request_policy(&request.transmit, self.policy)
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

        if check_privileges && !self.dry_run {
            let spec_for_check = Arc::clone(&spec);
            tokio::task::spawn_blocking(move || Self::check_privileges(spec_for_check.as_ref()))
                .await
                .context("privilege check task failed")??;
        }

        let plan = self.plan(Arc::clone(&spec)).await?;
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
        let policy = self.policy;
        let dry_run = self.dry_run;
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
}
