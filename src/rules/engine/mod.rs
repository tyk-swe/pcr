// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::sync::Arc;

use log::{debug, error, trace, warn};
use tokio::runtime::Handle;

use crate::rules::config::RuleExecutorConfig;
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
pub(crate) struct RuleEngine {
    rules: Vec<Rule>,
    sender: Option<Arc<dyn RuleSendDispatcher>>,
    task_executor: Arc<BoundedExecutor>,
}

impl RuleEngine {
    pub(crate) fn new_configured(
        config: RuleExecutorConfig,
    ) -> std::result::Result<Self, RuleError> {
        Self::new_configured_with_runtime_source(config, None)
    }

    pub(crate) fn new_configured_with_runtime_handle(
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

    pub(crate) fn configure_sender<D>(&mut self, sender: D)
    where
        D: RuleSendDispatcher + 'static,
    {
        self.sender = Some(Arc::new(sender));
    }

    fn sender(&self) -> Option<&dyn RuleSendDispatcher> {
        self.sender.as_deref()
    }

    pub(crate) fn load_rules_from_path_with_options<P: AsRef<std::path::Path>>(
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

        Ok(RuleLoadReport::new(parsed))
    }

    #[cfg(feature = "daemon")]
    pub(crate) fn load_from_path<P: AsRef<std::path::Path>>(&mut self, path: P) -> Result<()> {
        self.rules = Self::load_rules_from_path(path)?;
        Ok(())
    }

    #[cfg(any(test, feature = "daemon", feature = "repl"))]
    pub(crate) fn len(&self) -> usize {
        self.rules.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub(crate) fn replace_rules(&mut self, rules: Vec<Rule>) {
        self.rules = rules;
    }

    pub(crate) fn notify_receive(&self, packet: &PacketContext) {
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

    #[cfg(any(test, feature = "daemon", feature = "repl"))]
    pub(crate) fn has_receive_triggers(&self) -> bool {
        self.rules
            .iter()
            .any(super::rule::Rule::triggers_on_receive)
    }

    #[cfg(any(test, feature = "daemon"))]
    pub(crate) fn has_timer_triggers(&self) -> bool {
        self.rules.iter().any(super::rule::Rule::triggers_on_timer)
    }

    pub(crate) fn has_startup_triggers(&self) -> bool {
        self.rules
            .iter()
            .any(|rule| matches!(&rule.trigger, RuleTrigger::Startup))
    }

    #[cfg(feature = "daemon")]
    pub(crate) fn run_timer_actions(&self) {
        for rule in &self.rules {
            if rule.triggers_on_timer() {
                let name = rule.name.as_deref().unwrap_or("<unnamed timer rule>");
                trace!("executing timer rule '{name}'");
                rule.execute(None, self.sender(), self.task_executor());
            }
        }
    }

    pub(crate) fn run_startup_actions(&self) {
        for rule in &self.rules {
            if matches!(&rule.trigger, RuleTrigger::Startup) {
                let name = rule.name.as_deref().unwrap_or("<unnamed startup rule>");
                trace!("executing startup rule '{name}'");
                rule.execute(None, self.sender(), self.task_executor());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::error::RuleActionError;
    use std::sync::{Arc, Mutex};

    const VALID_RULE: &str = r#"
- name: log-tcp
  trigger: receive
  condition:
    description:
      contains: TCP
      case_insensitive: true
  actions:
    - type: log
      level: info
      message: "packet {description}"
    "#;

    fn load_rules(input: &str) -> Result<RuleLoadReport> {
        RuleEngine::load_rules_from_str_with_source(
            input,
            "<test-rules>".to_string(),
            RuleLoadOptions {
                log_diagnostics: false,
                ..Default::default()
            },
        )
    }

    fn load_rules_with_options(input: &str, options: RuleLoadOptions) -> Result<RuleLoadReport> {
        RuleEngine::load_rules_from_str_with_source(input, "<test-rules>".to_string(), options)
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct DispatchRecord {
        rule_name: String,
        packet_present: bool,
        rendered_destination: Option<String>,
    }

    #[derive(Debug, Clone, Default)]
    struct RecordingDispatcher {
        records: Arc<Mutex<Vec<DispatchRecord>>>,
    }

    impl RecordingDispatcher {
        fn records(&self) -> Vec<DispatchRecord> {
            self.records.lock().unwrap().clone()
        }
    }

    impl RuleSendDispatcher for RecordingDispatcher {
        fn dispatch(
            &self,
            rule_name: &str,
            template: &crate::rules::send::RuleSendTemplate,
            packet: Option<&PacketContext>,
        ) -> std::result::Result<(), RuleError> {
            let rendered = template.render(packet);
            self.records.lock().unwrap().push(DispatchRecord {
                rule_name: rule_name.to_string(),
                packet_present: packet.is_some(),
                rendered_destination: rendered.destination.destination,
            });
            Ok(())
        }
    }

    fn packet(description: &str) -> PacketContext {
        PacketContext {
            description: description.to_string(),
            source: Some("192.0.2.10".to_string()),
            destination: Some("198.51.100.20".to_string()),
            length: 40,
            timestamp: std::time::SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn load_rules_from_str_parses_valid_rule() {
        let rules = load_rules(VALID_RULE).unwrap().into_rules();

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name.as_deref(), Some("log-tcp"));
    }

    #[test]
    fn load_rules_from_str_rejects_empty_rule_list() {
        let err = load_rules("[]").unwrap_err();

        assert!(matches!(err, RuleError::EmptyRulesFile));
    }

    #[test]
    fn unknown_fields_are_accepted_as_warnings_by_default() {
        let yaml = r#"
- name: unknowns
  unexpected_rule_field: true
  condition:
    description:
      contains: TCP
      extra_matcher_field: true
  actions:
    - type: log
      message: hi
      extra_action_field: true
"#;
        let rules = load_rules_with_options(yaml, RuleLoadOptions::default())
            .unwrap()
            .into_rules();

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name.as_deref(), Some("unknowns"));
    }

    #[test]
    fn unknown_fields_are_errors_in_strict_mode() {
        let yaml = r#"
- name: strict
  actions:
    - type: send
      payload:
        data: hi
        unknown_payload_field: true
"#;
        let err = load_rules_with_options(
            yaml,
            RuleLoadOptions {
                strict: true,
                log_diagnostics: false,
            },
        )
        .unwrap_err();

        assert!(matches!(
            err,
            RuleError::Validation {
                errors: 1,
                diagnostics
            } if diagnostics[0].path == "rules[0].actions[0].payload.unknown_payload_field"
                && diagnostics[0].severity == RuleDiagnosticSeverity::Error
        ));
    }

    #[test]
    fn missing_action_from_yaml_includes_rule_context() {
        let err = load_rules(
            r#"
- name: no-actions
  trigger: receive
"#,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            RuleError::MissingAction {
                rule_index: 0,
                rule,
                ..
            } if rule == "no-actions"
        ));
    }

    #[test]
    fn command_definition_errors_are_wrapped_with_action_context() {
        let err = load_rules(
            r#"
- name: command
  actions:
    - type: command
      program: /bin/echo
      enabled: true
"#,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            RuleError::ActionContext {
                rule_index: 0,
                action_index: 0,
                source: RuleActionError::MissingCommandAllowlist,
                ..
            }
        ));
    }

    #[test]
    fn legacy_send_options_wrapper_is_rejected_from_yaml() {
        let err = load_rules(
            r#"
- name: legacy-send
  actions:
    - type: send
      options:
        payload:
          data: hi
"#,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            RuleError::ActionContext {
                source: RuleActionError::LegacySendOptionsWrapper,
                ..
            }
        ));
    }

    #[test]
    fn rule_engine_reports_trigger_presence_after_replace() {
        let rules = load_rules(
            r#"
- name: timer
  trigger: timer
  actions:
    - type: log
      message: timer
- name: startup
  trigger: startup
  actions:
    - type: log
      message: startup
"#,
        )
        .unwrap()
        .into_rules();
        let mut engine = RuleEngine::new_configured(RuleExecutorConfig {
            workers: 1,
            queue_capacity: 1,
        })
        .unwrap();

        engine.replace_rules(rules);

        assert_eq!(engine.len(), 2);
        assert!(!engine.has_receive_triggers());
        assert!(engine.has_timer_triggers());
        assert!(engine.has_startup_triggers());
    }

    #[test]
    fn notify_receive_executes_only_matching_receive_rules() {
        let rules = load_rules(
            r#"
- name: receive-match
  trigger: receive
  condition:
    description:
      contains: TCP
  actions:
    - type: send
      destination:
        destination: "{source}"
- name: receive-miss
  trigger: receive
  condition:
    description:
      contains: UDP
  actions:
    - type: send
      destination:
        destination: miss
- name: startup-only
  trigger: startup
  actions:
    - type: send
      destination:
        destination: startup
"#,
        )
        .unwrap()
        .into_rules();
        let dispatcher = RecordingDispatcher::default();
        let mut engine = RuleEngine::new_configured(RuleExecutorConfig {
            workers: 1,
            queue_capacity: 1,
        })
        .unwrap();
        engine.configure_sender(dispatcher.clone());
        engine.replace_rules(rules);

        engine.notify_receive(&packet("TCP SYN"));

        assert_eq!(
            dispatcher.records(),
            vec![DispatchRecord {
                rule_name: "receive-match".to_string(),
                packet_present: true,
                rendered_destination: Some("192.0.2.10".to_string()),
            }]
        );
    }

    #[test]
    fn run_startup_actions_executes_only_startup_rules_without_packet_context() {
        let rules = load_rules(
            r#"
- name: receive-only
  trigger: receive
  actions:
    - type: send
      destination:
        destination: receive
- name: startup-only
  trigger: startup
  actions:
    - type: send
      destination:
        destination: "{source}"
"#,
        )
        .unwrap()
        .into_rules();
        let dispatcher = RecordingDispatcher::default();
        let mut engine = RuleEngine::new_configured(RuleExecutorConfig {
            workers: 1,
            queue_capacity: 1,
        })
        .unwrap();
        engine.configure_sender(dispatcher.clone());
        engine.replace_rules(rules);

        engine.run_startup_actions();

        assert_eq!(
            dispatcher.records(),
            vec![DispatchRecord {
                rule_name: "startup-only".to_string(),
                packet_present: false,
                rendered_destination: Some("<unknown>".to_string()),
            }]
        );
    }
}
