// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::{Context, Result};
use log::{debug, info};
use std::sync::Arc;

use crate::domain::policy::TrafficMode;
use crate::domain::request::PacketRequest;
use crate::domain::spec::PacketSpec;
use crate::domain::transmission::TransmissionPlan;
use crate::engine::core::Engine;
use crate::engine::error::{EngineError, EngineResult};

pub struct OneShotFlow<'engine> {
    engine: &'engine mut Engine,
    request: PacketRequest,
    spec: Option<std::sync::Arc<PacketSpec>>,
    plan: Option<TransmissionPlan>,
}

impl<'engine> OneShotFlow<'engine> {
    pub fn new(engine: &'engine mut Engine, request: PacketRequest) -> Self {
        Self {
            engine,
            request,
            spec: None,
            plan: None,
        }
    }

    pub async fn with_spec(mut self) -> Result<Self> {
        self.log_one_shot_entry();
        let request = self.request.clone();
        let spec = self.engine.send.resolve_spec(request).await?;
        self.announce_listener(spec.as_ref());
        self.spec = Some(spec);
        Ok(self)
    }

    pub fn with_policy_validation(self) -> Result<Self> {
        self.engine.send.validate_request_policy(&self.request)?;
        Ok(self)
    }

    pub async fn with_rules(self) -> Result<Self> {
        if let Some(rules_file) = self.spec()?.rules_file.clone() {
            let path = rules_file.clone();
            let rules = tokio::task::spawn_blocking(move || {
                crate::rules::RuleEngine::load_rules_from_path(&path).map_err(|e| {
                    EngineError::rule_load(path.to_string_lossy().into_owned(), e.into())
                })
            })
            .await
            .context("rule loading task failed")??;

            self.engine.rules.replace_rules(rules);
        }
        Ok(self)
    }

    pub fn with_startup_rules(self) -> Self {
        if self.engine.rules.has_startup_triggers() && !self.engine.config.dry_run {
            self.engine.rules.run_startup_actions();
        }
        self
    }

    pub async fn with_authorized_preflight_traffic(mut self) -> Result<Self> {
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

    pub async fn with_preflight(self) -> Result<Self> {
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

    pub async fn with_plan(mut self) -> Result<Self> {
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

    pub fn with_preflight_output(self) -> Result<Self> {
        let spec = self.spec()?;
        let plan = self.plan()?;
        self.emit_preflight_summary(spec, plan)?;
        Ok(self)
    }

    pub async fn execute(mut self) -> Result<()> {
        let spec = self.take_spec()?;
        let plan = self.take_plan()?;
        self.engine.send.execute_plan(plan).await?;
        if !self.engine.config.dry_run {
            self.maybe_run_listener(spec.as_ref()).await?;
        }
        Ok(())
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

    fn announce_listener(&self, plan: &PacketSpec) {
        if plan.listener.enabled && plan.listener.implicit {
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
            .event_sink
            .emit_preflight_summary(spec, plan)
            .map_err(EngineError::PreflightSummary)
    }

    async fn maybe_run_listener(&mut self, plan: &PacketSpec) -> Result<()> {
        if plan.listener.enabled {
            self.engine
                .dependencies
                .listener_runner
                .run_for_packet(
                    plan.listener.clone(),
                    plan.target.interface.clone(),
                    self.engine.listener_handler(),
                )
                .await?;
        }
        Ok(())
    }
}
