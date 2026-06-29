// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use serde::de::IgnoredAny;
use serde::Deserialize;

use crate::engine::request::PacketRequest;
use crate::rules::error::{RuleActionError, RuleError};
use crate::rules::executor::{BoundedExecutor, RuleSendExecutor, RuleSendTemplate};
use crate::rules::model::{PacketContext, RuleLogLevel};

type Result<T> = std::result::Result<T, RuleError>;

pub(crate) mod command;
mod logging;

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleActionDocument {
    Log {
        message: String,
        #[serde(default)]
        level: Option<RuleLogLevel>,
    },
    Command {
        program: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        timeout_seconds: Option<u64>,
        #[serde(default)]
        enabled: bool,
        #[serde(default)]
        allowed_programs: Vec<String>,
        #[serde(default)]
        working_dir: Option<String>,
    },
    Send {
        #[serde(default)]
        #[serde(rename = "options")]
        legacy_options: Option<IgnoredAny>,
        #[serde(default)]
        #[serde(flatten)]
        request: Box<PacketRequest>,
    },
}

#[derive(Debug, Clone)]
pub enum RuleAction {
    Log {
        level: RuleLogLevel,
        message: String,
    },
    Command(command::CommandAction),
    Send(Box<RuleSendTemplate>),
}

impl TryFrom<RuleActionDocument> for RuleAction {
    type Error = RuleError;

    fn try_from(value: RuleActionDocument) -> Result<Self> {
        match value {
            RuleActionDocument::Log { message, level } => {
                logging::validate_message(&message)?;
                Ok(RuleAction::Log {
                    level: level.unwrap_or_default(),
                    message,
                })
            }
            RuleActionDocument::Command {
                program,
                args,
                timeout_seconds,
                enabled,
                allowed_programs,
                working_dir,
            } => {
                let command_action = command::CommandAction::from_document(
                    program,
                    args,
                    timeout_seconds,
                    enabled,
                    allowed_programs,
                    working_dir,
                )?;

                Ok(RuleAction::Command(command_action))
            }
            RuleActionDocument::Send {
                legacy_options,
                request,
            } => {
                if legacy_options.is_some() {
                    return Err(RuleActionError::LegacySendOptionsWrapper.into());
                }
                Ok(RuleAction::Send(Box::new(RuleSendTemplate::new(*request))))
            }
        }
    }
}

impl RuleAction {
    pub fn execute(
        &self,
        rule_name: &str,
        packet: Option<&PacketContext>,
        sender: Option<&RuleSendExecutor>,
        task_executor: &BoundedExecutor,
    ) -> Result<()> {
        match self {
            RuleAction::Log { level, message } => {
                logging::execute(rule_name, packet, *level, message);
                Ok(())
            }
            RuleAction::Command(command_action) => {
                command_action.execute(rule_name, packet, task_executor)
            }
            RuleAction::Send(template) => {
                let sender = sender.ok_or_else(|| RuleActionError::MissingSendExecutor {
                    rule: rule_name.to_string(),
                })?;
                sender.dispatch(rule_name, template.as_ref(), packet)
            }
        }
    }
}
