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
use crate::domain::request::PacketRequest;
use crate::engine::config::EngineConfig;
use crate::engine::error::{EngineError, EngineResult};
use crate::engine::oneshot::OneShotFlow;
use crate::engine::ports::EngineDependencies;
use crate::engine::rule_send::{RuleSendConfig, RuleSendExecutor};
use crate::engine::send::SendUseCase;
use crate::rules::RuleEngine;

pub struct Engine {
    pub(crate) config: EngineConfig,
    pub(crate) send: Arc<SendUseCase>,
    pub(crate) dependencies: EngineDependencies,
    pub(crate) rules: RuleEngine,
    #[cfg(feature = "daemon")]
    daemon_rules_preloaded: bool,
}

impl Engine {
    pub fn new(config: EngineConfig, dependencies: EngineDependencies) -> EngineResult<Self> {
        Self::new_with_optional_runtime_handle(config, dependencies, None)
    }

    pub fn new_with_runtime_handle(
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
            config.traffic_policy.with_dry_run(config.dry_run),
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

    pub async fn run_one_shot(&mut self, request: PacketRequest) -> Result<()> {
        OneShotFlow::new(self, request)
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

    #[cfg(feature = "daemon")]
    pub async fn run_daemon(&mut self, opts: &DaemonRequest) -> Result<()> {
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
            Arc::clone(&self.dependencies.event_sink),
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
    pub async fn run_listener(&mut self, opts: &ListenRequest) -> Result<()> {
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
    pub async fn run_traceroute(&mut self, opts: &TracerouteRequest) -> Result<()> {
        let policy = self.config.traffic_policy.with_dry_run(self.config.dry_run);
        let prepared = self
            .dependencies
            .traceroute_runner
            .prepare(opts.clone(), policy)
            .await?;
        self.config
            .traffic_policy
            .with_dry_run(self.config.dry_run)
            .authorize(prepared.traffic_plan())
            .map_err(|e| EngineError::Traceroute(e.into()))?;

        if self.config.dry_run {
            self.dependencies
                .event_sink
                .emit_traffic_plan_summary(prepared.traffic_plan())?;
            return Ok(());
        }
        info!(
            "Running traceroute to {} max_ttl={} probes={}",
            opts.destination, opts.max_ttl, opts.probes
        );
        prepared.run().await
    }

    pub async fn run_dns_query(&mut self, options: &DnsRequest) -> Result<String> {
        let policy = self.config.traffic_policy.with_dry_run(self.config.dry_run);
        let prepared = self
            .dependencies
            .dns_client
            .prepare(options.clone(), policy)
            .await?;
        self.config
            .traffic_policy
            .with_dry_run(self.config.dry_run)
            .authorize(prepared.traffic_plan())?;

        if self.config.dry_run {
            info!(
                "Dry-run: DNS query for {} {} via {}",
                options.domain, options.record_type, options.server
            );
            return self.dependencies.event_sink.format_dns_dry_run(options);
        }
        let result = prepared.resolve(options.clone()).await?;
        self.dependencies.event_sink.format_dns_response(&result)
    }

    #[cfg(feature = "scan")]
    pub async fn run_scan(&mut self, command: &ScanRequest) -> Result<()> {
        let policy = self.config.traffic_policy.with_dry_run(self.config.dry_run);
        let prepared = self
            .dependencies
            .scan_runner
            .prepare(command.clone(), policy)
            .await?;
        self.config
            .traffic_policy
            .with_dry_run(self.config.dry_run)
            .authorize(prepared.traffic_plan())
            .map_err(|e| EngineError::Scan(e.into()))?;

        if self.config.dry_run {
            self.dependencies
                .event_sink
                .emit_traffic_plan_summary(prepared.traffic_plan())?;
            return Ok(());
        }
        prepared.run().await
    }

    #[cfg(feature = "fuzz")]
    pub async fn run_fuzz(&mut self, options: &FuzzRequest) -> Result<()> {
        let policy = self.config.traffic_policy.with_dry_run(self.config.dry_run);
        let plan = self
            .dependencies
            .fuzz_runner
            .traffic_plan(options.clone(), policy)
            .await?;
        self.config
            .traffic_policy
            .with_dry_run(self.config.dry_run)
            .authorize(&plan)
            .map_err(|e| EngineError::TransmissionPlan(e.into()))?;

        if self.config.dry_run {
            self.dependencies
                .event_sink
                .emit_traffic_plan_summary(&plan)?;
            return Ok(());
        }
        self.dependencies
            .fuzz_runner
            .run(options.clone(), policy)
            .await
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn has_receive_rules(&self) -> bool {
        self.rules.has_receive_triggers()
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    pub(crate) fn listener_handler(&self) -> crate::engine::ports::ListenerEventHandler {
        let event_sink = Arc::clone(&self.dependencies.event_sink);
        let rules = self.rules.clone();

        Arc::new(move |event| {
            event_sink.emit_listener_event(&event);

            if rules.is_empty() {
                return;
            }

            let context = crate::rules::PacketContext::from_listener_event(&event);
            rules.notify_receive(&context);
        })
    }
}
