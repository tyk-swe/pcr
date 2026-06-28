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
            Some(config.allow_unbounded_sends),
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
            .with_rules()
            .await?
            .with_preflight()
            .await?
            .with_plan()
            .await?
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
        if self.config.dry_run {
            info!(
                "Dry-run: traceroute to {} max_ttl={} probes={} protocol={:?}",
                opts.destination, opts.max_ttl, opts.probes, opts.protocol
            );
            return Ok(());
        }
        info!(
            "Running traceroute to {} max_ttl={} probes={}",
            opts.destination, opts.max_ttl, opts.probes
        );
        crate::network::tools::traceroute::run(opts, &self.config).await
    }

    pub async fn run_dns_query(&mut self, options: &DnsRequest) -> Result<String> {
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
        let result = crate::network::protocols::dns::resolve(options, &self.config).await?;
        match self.config.output_format {
            Some(OutputFormat::Json) => crate::output::format_dns_message_json(&result),
            _ => Ok(crate::output::format_dns_message(&result)),
        }
    }

    #[cfg(feature = "scan")]
    pub async fn run_scan(&mut self, command: &ScanRequest) -> Result<()> {
        if self.config.dry_run {
            info!(
                "Dry-run: scan would execute command={:?}",
                std::mem::discriminant(command)
            );
            return Ok(());
        }
        crate::network::tools::scan::run_command(command, &self.config).await
    }

    #[cfg(feature = "fuzz")]
    pub async fn run_fuzz(&mut self, options: &FuzzRequest) -> Result<()> {
        if self.config.dry_run {
            info!(
                "Dry-run: fuzz would target {} protocol={:?} strategy={:?} count={}",
                options.target, options.protocol, options.strategy, options.count
            );
            return Ok(());
        }
        let config = crate::network::tools::fuzz::FuzzConfig::try_from(options)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::OutputFormat;
    use std::fs;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn config_with_overrides() -> EngineConfig {
        EngineConfig {
            output_format: Some(OutputFormat::Hex),
            prometheus_bind: Some("127.0.0.1:9898".to_string()),
            rule_workers: None,
            rule_queue: None,
            send_workers: None,
            send_queue: None,
            allow_unbounded_sends: false,
            dry_run: false,
        }
    }

    fn write_rules(docs: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("failed to create temporary rule file");
        writeln!(file, "{}", docs.trim()).expect("failed to write rules");
        file
    }

    #[test]
    fn engine_rule_count_reflects_loaded_documents() {
        let mut engine = Engine::new(config_with_overrides()).expect("engine initialisation");
        let rules = r#"
- name: "log inbound"
  trigger: on_receive
  actions:
    - type: log
      message: "got {description}"
- name: "startup"
  trigger: on_startup
  actions:
    - type: log
      message: "boot"
"#;
        let file = write_rules(rules);

        engine
            .rules
            .load_from_path(file.path().to_str().unwrap())
            .expect("rules should load successfully");

        assert_eq!(engine.rule_count(), 2);
        assert!(engine.has_receive_rules());
        assert!(engine.rules.has_startup_triggers());
    }

    #[test]
    fn engine_rules_can_be_reloaded_and_replaced() {
        let mut engine = Engine::new(config_with_overrides()).expect("engine initialisation");

        let initial_rules = r#"
- name: "first"
  trigger: on_receive
  actions:
    - type: log
      message: "a"
"#;
        let file = write_rules(initial_rules);
        engine
            .rules
            .load_from_path(file.path().to_str().unwrap())
            .expect("initial rules should load");
        assert_eq!(engine.rule_count(), 1);
        assert!(engine.has_receive_rules());

        let replacement_rules = r#"
- name: "only-startup"
  trigger: on_startup
  actions:
    - type: log
      message: "boot"
"#;
        fs::write(file.path(), replacement_rules.trim()).expect("writing replacement rules");

        engine
            .rules
            .load_from_path(file.path().to_str().unwrap())
            .expect("replacement rules should load");

        assert_eq!(engine.rule_count(), 1);
        assert!(!engine.has_receive_rules());
        assert!(engine.rules.has_startup_triggers());
    }

    #[cfg(feature = "daemon")]
    #[test]
    fn daemon_initialization_loads_rules() {
        let mut engine = Engine::new(config_with_overrides()).expect("engine initialisation");

        let rules = r#"
- name: "startup"
  trigger: on_startup
  actions:
    - type: log
      message: "boot"
"#;
        let file = write_rules(rules);
        let rules_file = file.path().to_str().map(|s| s.to_string());

        engine
            .init_daemon_rules(rules_file.as_ref())
            .expect("daemon init");

        assert_eq!(engine.rule_count(), 1);
        // The rule is loaded, but triggers are NOT run here.
        assert!(engine.rules.has_startup_triggers());
    }

    #[cfg(feature = "daemon")]
    #[test]
    fn daemon_preflight_installation_marks_rules_prepared() {
        let mut engine = Engine::new(config_with_overrides()).expect("engine initialisation");

        let rules = r#"
- name: "startup"
  trigger: on_startup
  actions:
    - type: log
      message: "boot"
"#;
        let file = write_rules(rules);
        let opts = DaemonRequest {
            rules_file: Some(file.path().to_string_lossy().into_owned()),
            foreground: Some(true),
            control_socket: None,
        };
        let preflight =
            crate::engine::daemon::preflight(&opts).expect("daemon preflight should load rules");

        engine.apply_daemon_preflight(preflight);

        assert_eq!(engine.rule_count(), 1);
        assert!(engine.daemon_rules_preloaded);
    }
}
