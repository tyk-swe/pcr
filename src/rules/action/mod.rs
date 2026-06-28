// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::process::Stdio;
use std::sync::Arc;

use log::{error, info, trace, warn};
use serde::de::IgnoredAny;
use serde::Deserialize;

use crate::engine::request::PacketRequest;
use crate::rules::config::{
    RULE_COMMAND_MAX_ARGS, RULE_COMMAND_MAX_ARG_LENGTH, RULE_COMMAND_MAX_PROGRAM_LENGTH,
    RULE_COMMAND_TIMEOUT_MAX_SECONDS, RULE_COMMAND_TIMEOUT_MIN_SECONDS,
    RULE_COMMAND_TIMEOUT_SECONDS,
};
use crate::rules::error::{RuleActionError, RuleError};
use crate::rules::executor::{BoundedExecutor, ExecutorError, RuleSendExecutor, RuleSendTemplate};
use crate::rules::model::{PacketContext, RuleLogLevel};
use crate::rules::template::{apply_template, log_message};
use crate::util::telemetry;

type Result<T> = std::result::Result<T, RuleError>;

fn contains_control_chars(input: &str) -> bool {
    input.chars().any(char::is_control)
}

fn validate_command_shape(
    program: &str,
    args: &[String],
) -> std::result::Result<(), RuleActionError> {
    if program.len() > RULE_COMMAND_MAX_PROGRAM_LENGTH {
        return Err(RuleActionError::CommandShapeLimitExceeded {
            details: format!(
                "program length {} exceeds maximum {}",
                program.len(),
                RULE_COMMAND_MAX_PROGRAM_LENGTH
            ),
        });
    }

    if args.len() > RULE_COMMAND_MAX_ARGS {
        return Err(RuleActionError::CommandShapeLimitExceeded {
            details: format!(
                "argument count {} exceeds maximum {}",
                args.len(),
                RULE_COMMAND_MAX_ARGS
            ),
        });
    }

    for (index, arg) in args.iter().enumerate() {
        if arg.len() > RULE_COMMAND_MAX_ARG_LENGTH {
            return Err(RuleActionError::CommandShapeLimitExceeded {
                details: format!(
                    "argument {index} length {} exceeds maximum {}",
                    arg.len(),
                    RULE_COMMAND_MAX_ARG_LENGTH
                ),
            });
        }
    }

    Ok(())
}

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
    Command {
        program: String,
        args: Vec<String>,
        timeout_seconds: u64,
    },
    Send(Box<RuleSendTemplate>),
}

impl TryFrom<RuleActionDocument> for RuleAction {
    type Error = RuleError;

    fn try_from(value: RuleActionDocument) -> Result<Self> {
        match value {
            RuleActionDocument::Log { message, level } => {
                if message.trim().is_empty() {
                    return Err(RuleActionError::EmptyLogMessage.into());
                }
                Ok(RuleAction::Log {
                    level: level.unwrap_or_default(),
                    message,
                })
            }
            RuleActionDocument::Command {
                program,
                args,
                timeout_seconds,
            } => {
                if program.trim().is_empty() {
                    return Err(RuleActionError::MissingCommandProgram.into());
                }
                if contains_control_chars(&program) {
                    return Err(RuleActionError::InvalidCommandProgram {
                        details: "program contains control characters".to_string(),
                    }
                    .into());
                }
                if program.trim_start().starts_with('-') {
                    return Err(RuleActionError::InvalidCommandProgram {
                        details: "program cannot start with '-'".to_string(),
                    }
                    .into());
                }
                for (index, arg) in args.iter().enumerate() {
                    if contains_control_chars(arg) {
                        return Err(RuleActionError::InvalidCommandArgument {
                            index,
                            details: "argument contains control characters".to_string(),
                        }
                        .into());
                    }
                }

                validate_command_shape(&program, &args)?;

                let timeout = timeout_seconds.unwrap_or(RULE_COMMAND_TIMEOUT_SECONDS);
                if !(RULE_COMMAND_TIMEOUT_MIN_SECONDS..=RULE_COMMAND_TIMEOUT_MAX_SECONDS)
                    .contains(&timeout)
                {
                    return Err(RuleActionError::CommandTimeoutOutOfRange {
                        timeout_seconds: timeout,
                        min_seconds: RULE_COMMAND_TIMEOUT_MIN_SECONDS,
                        max_seconds: RULE_COMMAND_TIMEOUT_MAX_SECONDS,
                    }
                    .into());
                }

                Ok(RuleAction::Command {
                    program,
                    args,
                    timeout_seconds: timeout,
                })
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
                let rendered = apply_template(message, packet);
                if rendered.trim().is_empty() {
                    warn!(
                        "rule '{}' log action ignored: empty message after template application",
                        rule_name
                    );
                    return Ok(());
                }
                log_message(*level, rule_name, &rendered);
                Ok(())
            }
            RuleAction::Command {
                program,
                args,
                timeout_seconds,
            } => {
                let rendered_program = apply_template(program, packet);
                if rendered_program.trim().is_empty() {
                    return Err(RuleActionError::InvalidCommandProgram {
                        details: format!(
                            "rule '{rule_name}' rendered program is empty after template application"
                        ),
                    }
                    .into());
                }
                if contains_control_chars(&rendered_program) {
                    return Err(RuleActionError::InvalidCommandProgram {
                        details: format!(
                            "rule '{rule_name}' rendered program contains control characters"
                        ),
                    }
                    .into());
                }
                if rendered_program.trim_start().starts_with('-') {
                    return Err(RuleActionError::InvalidCommandProgram {
                        details: format!(
                            "rule '{rule_name}' rendered program cannot start with '-'"
                        ),
                    }
                    .into());
                }

                let mut rendered_args = Vec::new();
                for (index, arg) in args.iter().enumerate() {
                    let rendered = apply_template(arg, packet);
                    if !arg.trim().starts_with('-') && rendered.trim().starts_with('-') {
                        warn!(
                            "rule '{}' command argument injection detected: template '{}' rendered to '{}' which looks like a flag. Blocking execution.",
                            rule_name, arg, rendered
                        );
                        telemetry::record_rule_action("command", "blocked_arg_injection");
                        return Err(RuleActionError::ArgumentInjection {
                            rule: rule_name.to_string(),
                            arg: rendered,
                        }
                        .into());
                    }
                    if contains_control_chars(&rendered) {
                        telemetry::record_rule_action("command", "blocked_invalid_arg");
                        return Err(RuleActionError::InvalidCommandArgument {
                            index,
                            details: format!(
                                "rule '{rule_name}' rendered argument contains control characters"
                            ),
                        }
                        .into());
                    }
                    rendered_args.push(rendered);
                }

                validate_command_shape(&rendered_program, &rendered_args)?;

                let command_summary = format!(
                    "program={:?} arg_count={}",
                    rendered_program,
                    rendered_args.len()
                );
                let rule_name_arc: Arc<str> = Arc::from(rule_name.to_string());
                let error_label = command_summary.clone();
                let task_rule_name = Arc::clone(&rule_name_arc);
                let timeout_duration = std::time::Duration::from_secs(*timeout_seconds);

                let spawn_result = task_executor.spawn_async(move || async move {
                    let rule_name = task_rule_name.as_ref();
                    trace!(
                        "rule '{}' executing command: {}",
                        rule_name,
                        command_summary
                    );
                    telemetry::record_rule_action("command", "started");

                    let child = tokio::process::Command::new(&rendered_program)
                        .args(&rendered_args)
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .kill_on_drop(true)
                        .spawn();

                    match child {
                        Ok(mut child) => {
                            match tokio::time::timeout(timeout_duration, child.wait()).await {
                                Ok(Ok(status)) => {
                                    if status.success() {
                                        telemetry::record_rule_action("command", "succeeded");
                                        info!(
                                            "rule '{}' command succeeded: {}",
                                            rule_name, command_summary
                                        );
                                    } else {
                                        telemetry::record_rule_action("command", "failed");
                                        warn!(
                                            "rule '{}' command exited with status {}: {}",
                                            rule_name, status, command_summary
                                        );
                                    }
                                }
                                Ok(Err(err)) => {
                                    telemetry::record_rule_action("command", "wait_error");
                                    error!(
                                        "rule '{}' failed to wait for command {}: {}",
                                        rule_name, command_summary, err
                                    );
                                }
                                Err(_) => {
                                    telemetry::record_rule_action("command", "timeout");
                                    warn!(
                                        "rule '{}' command timed out after {:?}: {}",
                                        rule_name, timeout_duration, command_summary
                                    );
                                    // Child is killed on drop
                                }
                            }
                        }
                        Err(err) => {
                            telemetry::record_rule_action("command", "spawn_error");
                            error!(
                                "rule '{}' failed to spawn command {}: {}",
                                rule_name, command_summary, err
                            );
                        }
                    }
                });

                match spawn_result {
                    Ok(()) => {
                        telemetry::record_rule_action("command", "queued");
                        Ok(())
                    }
                    Err(ExecutorError::QueueFull) => {
                        warn!(
                            "rule '{}' command dropped: executor queue is full ({})",
                            rule_name_arc.as_ref(),
                            error_label
                        );
                        telemetry::record_rule_executor_drop("command", "queue_full");
                        Err(RuleActionError::CommandQueueFull {
                            rule: rule_name.to_string(),
                            details: error_label,
                        }
                        .into())
                    }
                    Err(ExecutorError::Closed) => {
                        error!(
                            "rule '{}' command execution failed: executor unavailable ({})",
                            rule_name_arc.as_ref(),
                            error_label
                        );
                        telemetry::record_rule_executor_drop("command", "executor_closed");
                        Err(RuleActionError::CommandExecutorUnavailable {
                            rule: rule_name.to_string(),
                            details: error_label,
                        }
                        .into())
                    }
                    Err(ExecutorError::RuntimeUnavailable(runtime_error)) => {
                        error!(
                            "rule '{}' command execution failed: executor runtime unavailable ({}): {}",
                            rule_name_arc.as_ref(),
                            error_label,
                            runtime_error
                        );
                        telemetry::record_rule_executor_drop("command", "runtime_unavailable");
                        Err(RuleActionError::CommandExecutorUnavailable {
                            rule: rule_name.to_string(),
                            details: error_label,
                        }
                        .into())
                    }
                }
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

#[cfg(test)]
mod tests;
