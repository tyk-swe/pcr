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
pub enum RuleTrigger {
    #[default]
    #[serde(alias = "on_receive")]
    Receive,
    #[serde(alias = "on_timer")]
    Timer,
    #[serde(alias = "on_startup")]
    Startup,
}

#[derive(Debug, Deserialize)]
pub struct RuleDocument {
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
pub struct Rule {
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

    pub fn triggers_on_receive(&self) -> bool {
        matches!(&self.trigger, RuleTrigger::Receive)
    }

    pub fn triggers_on_timer(&self) -> bool {
        matches!(&self.trigger, RuleTrigger::Timer)
    }

    pub fn matches(&self, packet: &PacketContext) -> bool {
        match &self.condition {
            Some(condition) => condition.matches(packet),
            None => true,
        }
    }

    pub fn execute(
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
