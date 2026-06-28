// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::{Context, Result};
use log::{debug, info};
use std::sync::Arc;

use crate::engine::core::Engine;
use crate::engine::request::PacketRequest;
use crate::engine::send::PacketSendService;
use crate::engine::spec::PacketSpec;
use crate::engine::{EngineError, EngineResult};
use crate::network::io::sender::TransmissionPlan;

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
        let spec = PacketSendService::from_config(&self.engine.config)
            .resolve_spec(request)
            .await?;
        self.announce_listener(spec.as_ref());
        self.spec = Some(spec);
        Ok(self)
    }

    pub fn with_policy_validation(self) -> Result<Self> {
        PacketSendService::from_config(&self.engine.config)
            .validate_request_policy(&self.request)?;
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
        let service = PacketSendService::from_config(&self.engine.config);

        if !self.engine.config.dry_run {
            service
                .authorize_spec_traffic(spec.as_ref(), crate::engine::policy::TrafficMode::Send)?;
            return Ok(self);
        }

        let plan = service.plan_dry_run(Arc::clone(&spec)).await?;
        service.authorize_transmission_plan(spec.as_ref(), &plan)?;
        self.plan = Some(plan);
        Ok(self)
    }

    pub async fn with_preflight(self) -> Result<Self> {
        let spec = Arc::clone(
            self.spec
                .as_ref()
                .context("packet spec missing; ensure with_spec() is called first")?,
        );
        PacketSendService::from_config(&self.engine.config).validate_spec_policy(spec.as_ref())?;

        if !self.engine.config.dry_run {
            tokio::task::spawn_blocking(move || PacketSendService::check_privileges(spec.as_ref()))
                .await
                .context("privilege check task failed")??;
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
        let service = PacketSendService::from_config(&self.engine.config);
        let plan = service.plan_live(Arc::clone(&spec)).await?;
        service.authorize_transmission_plan(spec.as_ref(), &plan)?;
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
        PacketSendService::from_config(&self.engine.config)
            .execute_plan(plan)
            .await?;
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
            .output
            .emit_preflight_summary(spec, plan, &self.engine.config)
            .map_err(EngineError::PreflightSummary)
    }

    async fn maybe_run_listener(&mut self, plan: &PacketSpec) -> Result<()> {
        if plan.listener.enabled {
            crate::network::io::listener::run_from_spec(
                &plan.listener,
                plan.target.interface.as_deref(),
                &self.engine.config,
                self.engine.listener_handler(),
            )
            .await
            .map_err(anyhow::Error::from)?;
        }
        Ok(())
    }

    pub fn check_privileges(plan: &PacketSpec) -> EngineResult<()> {
        PacketSendService::check_privileges(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::config::EngineConfig;
    use crate::engine::policy::{TrafficBudget, TrafficPolicy};
    use crate::engine::spec::{
        DestinationSpec, Ipv6Spec, Layer2Spec, ListenerSpec, LoggingSpec, PayloadSource,
        PayloadSpec, TargetAddress, TransmissionSpec, TransportSpec,
    };
    use std::io::Write;
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::Duration;
    use tempfile::NamedTempFile;

    fn test_config() -> EngineConfig {
        EngineConfig {
            output_format: None,
            prometheus_bind: None,
            rule_workers: None,
            rule_queue: None,
            send_workers: None,
            send_queue: None,
            traffic_policy: TrafficPolicy::default(),
            dry_run: false,
        }
    }

    #[test]
    fn ensure_privileges_checks_layer3_transmit_modes() {
        let plan = PacketSpec {
            target: DestinationSpec {
                address: Some(TargetAddress::Host("example.test".to_string())),
                interface: None,
            },
            layer2: Layer2Spec::default(),
            ip: None,
            ipv6: Ipv6Spec::default(),
            transport: TransportSpec::Auto,
            payload: PayloadSpec {
                source: PayloadSource::Empty,
            },
            transmit: TransmissionSpec {
                force_layer3: true,
                ..Default::default()
            },
            listener: ListenerSpec::default(),
            rules_file: None,
            logging: LoggingSpec::default(),
        };

        // We need a dummy Engine.
        let mut engine = Engine::new(test_config()).expect("engine initialisation");
        let _flow = OneShotFlow::new(&mut engine, PacketRequest::default());

        let has_raw_capability = crate::util::privileges::assert_raw_socket_capability().is_ok();

        let result = OneShotFlow::check_privileges(&plan);
        if has_raw_capability {
            assert!(result.is_ok(), "privileged execution should pass");
        } else {
            assert!(
                result.is_err(),
                "missing CAP_NET_RAW should surface as an error in layer3-only mode"
            );
        }
    }

    #[tokio::test]
    async fn expanded_plan_policy_rejection_skips_startup_rules() {
        use crate::rules::test_support;

        let _executor_guard = test_support::executor_lock();
        let mut rules_file = NamedTempFile::new().expect("create temporary rule file");
        writeln!(
            rules_file,
            r#"
- name: "startup"
  trigger: on_startup
  actions:
    - type: send
"#
        )
        .expect("write rules");

        let (tx, rx) = mpsc::channel();
        let tx = Arc::new(Mutex::new(tx));
        let _hook_guard = test_support::send_hook_guard(Some(Arc::new(move |rule_name, _| {
            tx.lock()
                .expect("startup hook mutex")
                .send(rule_name)
                .expect("startup hook receiver");
            Ok(())
        })));

        let mut config = test_config();
        config.traffic_policy = TrafficPolicy {
            budget: TrafficBudget {
                max_estimated_packets: 1,
                ..Default::default()
            },
            ..Default::default()
        };

        let mut request = PacketRequest::default();
        request.destination.destination = Some("127.0.0.1".to_string());
        request.destination.interface = Some("lo".to_string());
        request.ip.fragment.mtu = Some(68);
        request.payload.random_payload_size = Some(512);
        request.transmit.force_layer3 = Some(true);
        request.rules_file = Some(rules_file.path().to_string_lossy().into_owned());

        let mut engine = Engine::new(config).expect("engine initialisation");
        let result = OneShotFlow::new(&mut engine, request)
            .with_policy_validation()
            .expect("request policy")
            .with_spec()
            .await
            .expect("spec")
            .with_authorized_preflight_traffic()
            .await
            .expect("spec traffic authorization")
            .with_rules()
            .await
            .expect("rules")
            .with_plan()
            .await;

        let error = match result {
            Ok(_) => panic!("expanded plan should exceed packet cap"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("packet_cap_exceeded"),
            "unexpected error: {error:#}"
        );
        assert_eq!(engine.rule_count(), 1, "rules should be loaded");
        assert!(
            rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "startup send action should not run after plan authorization fails"
        );
    }
}
