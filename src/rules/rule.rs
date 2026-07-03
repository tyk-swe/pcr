// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::rules::action::{RuleAction, RuleActionDocument};
use crate::rules::condition::{RuleCondition, RuleConditionDocument};
use crate::rules::error::RuleError;
use crate::rules::executor::BoundedExecutor;
use crate::rules::model::PacketContext;
use crate::rules::send::RuleSendDispatcher;
use log::warn;
use serde::Deserialize;

type Result<T> = std::result::Result<T, RuleError>;

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuleTrigger {
    #[default]
    #[serde(alias = "on_receive")]
    Receive,
    #[serde(alias = "on_timer")]
    Timer,
    #[serde(alias = "on_startup")]
    Startup,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RuleDocument {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub trigger: RuleTrigger,
    #[serde(default)]
    pub condition: Option<RuleConditionDocument>,
    #[serde(default)]
    pub actions: Vec<RuleActionDocument>,
}

#[derive(Debug, Clone)]
pub(crate) struct Rule {
    pub name: Option<String>,
    pub trigger: RuleTrigger,
    pub actions: Vec<RuleAction>,
    pub condition: Option<RuleCondition>,
}

impl TryFrom<RuleDocument> for Rule {
    type Error = RuleError;

    fn try_from(doc: RuleDocument) -> Result<Self> {
        Self::from_document(doc, 0)
    }
}

impl Rule {
    pub(crate) fn from_document(doc: RuleDocument, rule_index: usize) -> Result<Self> {
        let RuleDocument {
            name,
            trigger,
            condition,
            actions,
        } = doc;
        let rule_name = name.clone();

        if actions.is_empty() {
            return Err(RuleError::missing_action(rule_index, rule_name));
        }

        let mut parsed_actions = Vec::with_capacity(actions.len());
        for (action_index, action) in actions.into_iter().enumerate() {
            match RuleAction::try_from(action) {
                Ok(action) => parsed_actions.push(action),
                Err(RuleError::Action(source)) => {
                    return Err(RuleError::action_context(
                        rule_index,
                        rule_name.as_deref(),
                        action_index,
                        source,
                    ));
                }
                Err(source) => {
                    return Err(RuleError::rule_context(
                        rule_index,
                        rule_name.as_deref(),
                        source,
                    ));
                }
            }
        }

        let condition = condition
            .map(RuleCondition::try_from)
            .transpose()
            .map_err(|source| RuleError::rule_context(rule_index, rule_name.as_deref(), source))?;

        Ok(Self {
            name,
            trigger,
            actions: parsed_actions,
            condition,
        })
    }

    pub(crate) fn triggers_on_receive(&self) -> bool {
        matches!(&self.trigger, RuleTrigger::Receive)
    }

    #[cfg(any(test, feature = "daemon"))]
    pub(crate) fn triggers_on_timer(&self) -> bool {
        matches!(&self.trigger, RuleTrigger::Timer)
    }

    pub(crate) fn matches(&self, packet: &PacketContext) -> bool {
        match &self.condition {
            Some(condition) => condition.matches(packet),
            None => true,
        }
    }

    pub(crate) fn execute(
        &self,
        packet: Option<&PacketContext>,
        sender: Option<&dyn RuleSendDispatcher>,
        task_executor: &BoundedExecutor,
    ) {
        let rule_name = self.name.as_deref().unwrap_or("<unnamed rule>").to_string();
        for action in &self.actions {
            if let Err(err) = action.execute(&rule_name, packet, sender, task_executor) {
                warn!("rule '{}' action failed: {err}", rule_name);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::action::RuleActionDocument;
    use crate::rules::condition::{MatcherDef, RuleConditionDocument};
    use crate::rules::error::RuleActionError;
    use crate::rules::model::RuleLogLevel;
    use std::time::SystemTime;

    fn log_action(message: &str) -> RuleActionDocument {
        RuleActionDocument::Log {
            message: message.to_string(),
            level: Some(RuleLogLevel::Info),
        }
    }

    fn packet(description: &str) -> PacketContext {
        PacketContext {
            description: description.to_string(),
            source: None,
            destination: None,
            length: 1,
            timestamp: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn rule_from_document_rejects_missing_actions_with_context() {
        let err = Rule::from_document(
            RuleDocument {
                name: Some("empty".to_string()),
                trigger: RuleTrigger::Receive,
                condition: None,
                actions: vec![],
            },
            2,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            RuleError::MissingAction {
                rule_index: 2,
                rule,
                ..
            } if rule == "empty"
        ));
    }

    #[test]
    fn rule_from_document_wraps_action_errors_with_action_context() {
        let err = Rule::from_document(
            RuleDocument {
                name: Some("bad-action".to_string()),
                trigger: RuleTrigger::Receive,
                condition: None,
                actions: vec![log_action(" ")],
            },
            1,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            RuleError::ActionContext {
                rule_index: 1,
                action_index: 0,
                source: RuleActionError::EmptyLogMessage,
                ..
            }
        ));
    }

    #[test]
    fn rule_from_document_builds_condition_and_actions() {
        let rule = Rule::from_document(
            RuleDocument {
                name: Some("tcp".to_string()),
                trigger: RuleTrigger::Timer,
                condition: Some(RuleConditionDocument {
                    description: Some(MatcherDef::Simple("tcp".to_string())),
                    ..Default::default()
                }),
                actions: vec![log_action("matched")],
            },
            0,
        )
        .unwrap();

        assert!(rule.triggers_on_timer());
        assert!(!rule.triggers_on_receive());
        assert!(rule.matches(&packet("TCP packet")));
        assert!(!rule.matches(&packet("UDP packet")));
        assert_eq!(rule.actions.len(), 1);
    }

    #[test]
    fn rule_without_condition_matches_every_packet() {
        let rule = Rule::from_document(
            RuleDocument {
                name: None,
                trigger: RuleTrigger::Receive,
                condition: None,
                actions: vec![log_action("matched")],
            },
            0,
        )
        .unwrap();

        assert!(rule.matches(&packet("anything")));
    }
}
