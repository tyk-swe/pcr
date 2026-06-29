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
use crate::engine::command::DaemonRequest;
use crate::engine::command::DnsRequest;
#[cfg(feature = "fuzz")]
use crate::engine::command::FuzzRequest;
#[cfg(feature = "pcap")]
use crate::engine::command::ListenRequest;
#[cfg(feature = "scan")]
use crate::engine::command::ScanRequest;
#[cfg(feature = "traceroute")]
use crate::engine::command::TracerouteRequest;
use crate::engine::config::EngineConfig;
use crate::engine::oneshot::OneShotFlow;
use crate::engine::request::PacketRequest;
use crate::engine::{EngineError, EngineResult};
use crate::output::OutputController;
use crate::output::OutputFormat;
use crate::rules::{RuleEngine, RuleSendExecutor};

pub struct Engine {
    pub(crate) config: EngineConfig,
    pub(crate) output: OutputController,
    pub(crate) rules: RuleEngine,
    #[cfg(feature = "daemon")]
    daemon_rules_preloaded: bool,
}

impl Engine {
    pub fn new(config: EngineConfig) -> EngineResult<Self> {
        Self::new_with_optional_runtime_handle(config, None)
    }

    pub fn new_with_runtime_handle(config: EngineConfig, handle: Handle) -> EngineResult<Self> {
        Self::new_with_optional_runtime_handle(config, Some(handle))
    }

    fn new_with_optional_runtime_handle(
        config: EngineConfig,
        handle: Option<Handle>,
    ) -> EngineResult<Self> {
        let rule_config = crate::rules::RuleExecutorConfig::from_options(
            config.rule_workers,
            config.rule_queue,
            None,
            Some(config.dry_run),
        );
        let send_config = crate::rules::RuleExecutorConfig::from_options(
            config.send_workers,
            config.send_queue,
            Some(config.traffic_policy),
            Some(config.dry_run),
        );

        let mut rules = match handle.as_ref() {
            Some(handle) => {
                RuleEngine::new_configured_with_runtime_handle(rule_config, handle.clone())
            }
            None => RuleEngine::new_configured(rule_config),
        }
        .map_err(|e| EngineError::RuleEngineInit(e.into()))?;
        let sender = match handle {
            Some(handle) => {
                RuleSendExecutor::new_configured_with_runtime_handle(send_config, handle)
            }
            None => RuleSendExecutor::new_configured(send_config),
        }
        .map_err(|e| EngineError::RuleSendExecutorInit(e.into()))?;
        rules.configure_sender(sender);
        Ok(Self {
            output: OutputController::new(config.output_format),
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
        crate::engine::daemon::run(opts, &self.config, &mut self.rules, &self.output).await
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
        crate::network::io::listener::run_command(opts, None, &self.config, self.listener_handler())
            .await
            .map_err(anyhow::Error::from)
    }

    #[cfg(feature = "traceroute")]
    pub async fn run_traceroute(&mut self, opts: &TracerouteRequest) -> Result<()> {
        let prepared = crate::network::tools::traceroute::prepare(opts, &self.config)?;
        self.config
            .traffic_policy
            .with_dry_run(self.config.dry_run)
            .authorize(&prepared.traffic_plan)
            .map_err(|e| EngineError::Traceroute(e.into()))?;

        if self.config.dry_run {
            self.output
                .emit_traffic_plan_summary(&prepared.traffic_plan)?;
            return Ok(());
        }
        info!(
            "Running traceroute to {} max_ttl={} probes={}",
            opts.destination, opts.max_ttl, opts.probes
        );
        crate::network::tools::traceroute::run_prepared(opts, &self.config, prepared).await
    }

    pub async fn run_dns_query(&mut self, options: &DnsRequest) -> Result<String> {
        let prepared = crate::network::protocols::dns::prepare(options, &self.config).await?;
        self.config
            .traffic_policy
            .with_dry_run(self.config.dry_run)
            .authorize(&prepared.traffic_plan)?;

        if self.config.dry_run {
            info!(
                "Dry-run: DNS query for {} {} via {}",
                options.domain, options.record_type, options.server
            );
            return match self.config.output_format {
                Some(OutputFormat::Json) => crate::output::format_dns_dry_run_json(options),
                _ => Ok(crate::output::format_dns_dry_run(options)),
            };
        }
        let result = crate::network::protocols::dns::resolve_prepared(options, prepared).await?;
        match self.config.output_format {
            Some(OutputFormat::Json) => crate::output::format_dns_message_json(&result),
            _ => Ok(crate::output::format_dns_message(&result)),
        }
    }

    #[cfg(feature = "scan")]
    pub async fn run_scan(&mut self, command: &ScanRequest) -> Result<()> {
        let prepared = crate::network::tools::scan::prepare(command, &self.config)?;
        self.config
            .traffic_policy
            .with_dry_run(self.config.dry_run)
            .authorize(&prepared.traffic_plan)
            .map_err(|e| EngineError::Scan(e.into()))?;

        if self.config.dry_run {
            self.output
                .emit_traffic_plan_summary(&prepared.traffic_plan)?;
            return Ok(());
        }
        crate::network::tools::scan::run_command(prepared.command(), &self.config).await
    }

    #[cfg(feature = "fuzz")]
    pub async fn run_fuzz(&mut self, options: &FuzzRequest) -> Result<()> {
        let mut config = crate::network::tools::fuzz::FuzzConfig::try_from(options)?;
        config.apply_traffic_policy(&self.config.traffic_policy);
        let plan = crate::network::tools::fuzz::traffic_plan(&config)?;
        self.config
            .traffic_policy
            .with_dry_run(self.config.dry_run)
            .authorize(&plan)
            .map_err(|e| EngineError::TransmissionPlan(e.into()))?;

        if self.config.dry_run {
            self.output.emit_traffic_plan_summary(&plan)?;
            return Ok(());
        }
        crate::network::tools::fuzz::run_fuzz(config).await?;
        Ok(())
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

    pub(crate) fn listener_handler(&self) -> crate::network::io::listener::ListenerEventHandler {
        let output = self.output.clone();
        let rules = self.rules.clone();

        Arc::new(move |event| {
            output.emit_listener_event(&event);

            if rules.is_empty() {
                return;
            }

            let context = crate::engine::event::listener_event_rule_context(&event);
            rules.notify_receive(&context);
        })
    }
}
