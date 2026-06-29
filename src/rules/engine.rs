// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::sync::Arc;

use log::{debug, error, trace, warn};
use tokio::runtime::Handle;

use crate::rules::config::{
    RuleExecutorConfig, RULE_EXECUTOR_QUEUE_CAPACITY, RULE_EXECUTOR_WORKERS,
};
use crate::rules::diagnostic::{
    RuleDiagnostic, RuleDiagnosticSeverity, RuleLoadOptions, RuleLoadReport,
};
use crate::rules::error::RuleError;
use crate::rules::executor::BoundedExecutor;
use crate::rules::model::PacketContext;
use crate::rules::rule::{Rule, RuleDocument, RuleTrigger};
use crate::rules::send::RuleSendDispatcher;
use crate::rules::yaml;
use crate::util::error::UtilError;

type Result<T> = std::result::Result<T, RuleError>;

mod schema;

use schema::collect_unknown_rule_schema_fields;

fn log_rule_diagnostics(diagnostics: &[RuleDiagnostic]) {
    for diagnostic in diagnostics {
        match diagnostic.severity {
            RuleDiagnosticSeverity::Warning => warn!("{diagnostic}"),
            RuleDiagnosticSeverity::Error => error!("{diagnostic}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuleEngine {
    rules: Vec<Rule>,
    sender: Option<Arc<dyn RuleSendDispatcher>>,
    task_executor: Arc<BoundedExecutor>,
}

impl RuleEngine {
    pub fn new() -> std::result::Result<Self, RuleError> {
        Self::new_configured(RuleExecutorConfig {
            workers: RULE_EXECUTOR_WORKERS,
            queue_capacity: RULE_EXECUTOR_QUEUE_CAPACITY,
        })
    }

    pub fn new_configured(config: RuleExecutorConfig) -> std::result::Result<Self, RuleError> {
        Self::new_configured_with_runtime_source(config, None)
    }

    pub fn new_with_runtime_handle(handle: Handle) -> std::result::Result<Self, RuleError> {
        Self::new_configured_with_runtime_handle(
            RuleExecutorConfig {
                workers: RULE_EXECUTOR_WORKERS,
                queue_capacity: RULE_EXECUTOR_QUEUE_CAPACITY,
            },
            handle,
        )
    }

    pub fn new_configured_with_runtime_handle(
        config: RuleExecutorConfig,
        handle: Handle,
    ) -> std::result::Result<Self, RuleError> {
        Self::new_configured_with_runtime_source(config, Some(handle))
    }

    fn new_configured_with_runtime_source(
        config: RuleExecutorConfig,
        handle: Option<Handle>,
    ) -> std::result::Result<Self, RuleError> {
        let task_executor = match handle {
            Some(handle) => BoundedExecutor::new_with_handle(
                handle,
                config.workers,
                config.workers + config.queue_capacity,
            )?,
            None => BoundedExecutor::new(
                "rule-worker",
                config.workers,
                config.workers + config.queue_capacity,
            )?,
        };

        Ok(Self {
            rules: Vec::new(),
            sender: None,
            task_executor: Arc::new(task_executor),
        })
    }

    fn task_executor(&self) -> &BoundedExecutor {
        &self.task_executor
    }

    pub fn configure_sender<D>(&mut self, sender: D)
    where
        D: RuleSendDispatcher + 'static,
    {
        self.sender = Some(Arc::new(sender));
    }

    fn sender(&self) -> Option<&dyn RuleSendDispatcher> {
        self.sender.as_deref()
    }

    pub fn validate_rules_from_path<P: AsRef<std::path::Path>>(path: P) -> Result<RuleLoadReport> {
        Self::load_rules_from_path_with_options(path, RuleLoadOptions::validation())
    }

    pub fn validate_rules_from_path_with_options<P: AsRef<std::path::Path>>(
        path: P,
        options: RuleLoadOptions,
    ) -> Result<RuleLoadReport> {
        Self::load_rules_from_path_with_options(path, options.with_diagnostic_logging(false))
    }

    pub fn validate_rules_from_str(input: &str) -> Result<RuleLoadReport> {
        Self::load_rules_from_str_with_options(input, RuleLoadOptions::validation())
    }

    pub fn validate_rules_from_str_with_options(
        input: &str,
        options: RuleLoadOptions,
    ) -> Result<RuleLoadReport> {
        Self::load_rules_from_str_with_options(input, options.with_diagnostic_logging(false))
    }

    pub fn load_rules_from_path_with_options<P: AsRef<std::path::Path>>(
        path: P,
        options: RuleLoadOptions,
    ) -> Result<RuleLoadReport> {
        let path = path.as_ref();
        let source_name = path.to_string_lossy().into_owned();
        let data = fs::read_to_string(path).map_err(|source| UtilError::Filesystem {
            path: source_name.clone(),
            source,
        })?;
        Self::load_rules_from_str_with_source(&data, source_name, options)
    }

    pub fn load_rules_from_str_with_options(
        input: &str,
        options: RuleLoadOptions,
    ) -> Result<RuleLoadReport> {
        Self::load_rules_from_str_with_source(input, "<rules>".to_string(), options)
    }

    pub(crate) fn load_rules_from_path<P: AsRef<std::path::Path>>(path: P) -> Result<Vec<Rule>> {
        Ok(Self::load_rules_from_path_with_options(path, RuleLoadOptions::default())?.into_rules())
    }

    fn load_rules_from_str_with_source(
        input: &str,
        source_name: String,
        options: RuleLoadOptions,
    ) -> Result<RuleLoadReport> {
        let raw_yaml: yaml::Value =
            yaml::from_str(input).map_err(|source| UtilError::ParseFile {
                path: source_name.clone(),
                format: "YAML".to_string(),
                source: Box::new(source),
            })?;
        let diagnostics =
            collect_unknown_rule_schema_fields(&raw_yaml, options.unknown_field_severity());
        if options.log_diagnostics {
            log_rule_diagnostics(&diagnostics);
        }
        let documents: Vec<RuleDocument> =
            yaml::from_value(raw_yaml).map_err(|source| UtilError::ParseFile {
                path: source_name,
                format: "YAML".to_string(),
                source: Box::new(source),
            })?;
        let mut parsed = Vec::with_capacity(documents.len());
        for (rule_index, doc) in documents.into_iter().enumerate() {
            parsed.push(Rule::from_document(doc, rule_index)?);
        }

        if parsed.is_empty() {
            return Err(RuleError::EmptyRulesFile);
        }

        if diagnostics.iter().any(RuleDiagnostic::is_error) {
            return Err(RuleError::validation(diagnostics));
        }

        Ok(RuleLoadReport::new(parsed, diagnostics))
    }

    pub fn load_from_path<P: AsRef<std::path::Path>>(&mut self, path: P) -> Result<()> {
        self.rules = Self::load_rules_from_path(path)?;
        Ok(())
    }

    pub fn load_from_path_with_options<P: AsRef<std::path::Path>>(
        &mut self,
        path: P,
        options: RuleLoadOptions,
    ) -> Result<RuleLoadReport> {
        let report = Self::load_rules_from_path_with_options(path, options)?;
        self.rules = report.clone().into_rules();
        Ok(report)
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub(crate) fn replace_rules(&mut self, rules: Vec<Rule>) {
        self.rules = rules;
    }

    pub fn notify_receive(&self, packet: &PacketContext) {
        for rule in &self.rules {
            if rule.triggers_on_receive() && rule.matches(packet) {
                let name = rule.name.as_deref().unwrap_or("<unnamed receive rule>");
                debug!(
                    "rule '{}' triggered by packet {} from {:?} to {:?} length {}",
                    name, packet.description, packet.source, packet.destination, packet.length
                );
                rule.execute(Some(packet), self.sender(), self.task_executor());
            }
        }
    }

    pub fn has_receive_triggers(&self) -> bool {
        self.rules.iter().any(|rule| rule.triggers_on_receive())
    }

    pub fn has_timer_triggers(&self) -> bool {
        self.rules.iter().any(|rule| rule.triggers_on_timer())
    }

    pub fn has_startup_triggers(&self) -> bool {
        self.rules
            .iter()
            .any(|rule| matches!(&rule.trigger, RuleTrigger::Startup))
    }

    pub fn run_timer_actions(&self) {
        for rule in &self.rules {
            if rule.triggers_on_timer() {
                let name = rule.name.as_deref().unwrap_or("<unnamed timer rule>");
                trace!("executing timer rule '{name}'");
                rule.execute(None, self.sender(), self.task_executor());
            }
        }
    }

    pub fn run_startup_actions(&self) {
        for rule in &self.rules {
            if matches!(&rule.trigger, RuleTrigger::Startup) {
                let name = rule.name.as_deref().unwrap_or("<unnamed startup rule>");
                trace!("executing startup rule '{name}'");
                rule.execute(None, self.sender(), self.task_executor());
            }
        }
    }
}
