// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use log::{error, info, trace, warn};

use crate::rules::config::{
    RULE_COMMAND_MAX_ARGS, RULE_COMMAND_MAX_ARG_LENGTH, RULE_COMMAND_MAX_PROGRAM_LENGTH,
    RULE_COMMAND_TIMEOUT_MAX_SECONDS, RULE_COMMAND_TIMEOUT_MIN_SECONDS,
    RULE_COMMAND_TIMEOUT_SECONDS,
};
use crate::rules::error::{RuleActionError, RuleError};
use crate::rules::executor::{BoundedExecutor, ExecutorError};
use crate::rules::model::PacketContext;
use crate::rules::template::apply_template;
use crate::util::telemetry;

type ActionResult<T> = std::result::Result<T, RuleActionError>;

struct RenderedCommand {
    program: String,
    args: Vec<String>,
    summary: String,
}

pub(super) fn validate_definition(
    program: &str,
    args: &[String],
    timeout_seconds: Option<u64>,
) -> ActionResult<u64> {
    validate_program(program)?;
    validate_definition_args(args)?;
    validate_shape(program, args)?;
    timeout_or_default(timeout_seconds)
}

pub(super) fn execute(
    rule_name: &str,
    packet: Option<&PacketContext>,
    program: &str,
    args: &[String],
    timeout_seconds: u64,
    task_executor: &BoundedExecutor,
) -> std::result::Result<(), RuleError> {
    let rendered = render_invocation(rule_name, packet, program, args)?;
    submit_command(
        rule_name,
        rendered,
        Duration::from_secs(timeout_seconds),
        task_executor,
    )
}

fn contains_control_chars(input: &str) -> bool {
    input.chars().any(char::is_control)
}

fn validate_program(program: &str) -> ActionResult<()> {
    if program.trim().is_empty() {
        return Err(RuleActionError::MissingCommandProgram);
    }
    if contains_control_chars(program) {
        return Err(RuleActionError::InvalidCommandProgram {
            details: "program contains control characters".to_string(),
        });
    }
    if program.trim_start().starts_with('-') {
        return Err(RuleActionError::InvalidCommandProgram {
            details: "program cannot start with '-'".to_string(),
        });
    }
    Ok(())
}

fn validate_definition_args(args: &[String]) -> ActionResult<()> {
    for (index, arg) in args.iter().enumerate() {
        if contains_control_chars(arg) {
            return Err(RuleActionError::InvalidCommandArgument {
                index,
                details: "argument contains control characters".to_string(),
            });
        }
    }
    Ok(())
}

fn timeout_or_default(timeout_seconds: Option<u64>) -> ActionResult<u64> {
    let timeout = timeout_seconds.unwrap_or(RULE_COMMAND_TIMEOUT_SECONDS);
    if !(RULE_COMMAND_TIMEOUT_MIN_SECONDS..=RULE_COMMAND_TIMEOUT_MAX_SECONDS).contains(&timeout) {
        return Err(RuleActionError::CommandTimeoutOutOfRange {
            timeout_seconds: timeout,
            min_seconds: RULE_COMMAND_TIMEOUT_MIN_SECONDS,
            max_seconds: RULE_COMMAND_TIMEOUT_MAX_SECONDS,
        });
    }
    Ok(timeout)
}

fn validate_shape(program: &str, args: &[String]) -> ActionResult<()> {
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

fn render_invocation(
    rule_name: &str,
    packet: Option<&PacketContext>,
    program: &str,
    args: &[String],
) -> ActionResult<RenderedCommand> {
    let rendered_program = apply_template(program, packet);
    validate_rendered_program(rule_name, &rendered_program)?;

    let mut rendered_args = Vec::with_capacity(args.len());
    for (index, arg) in args.iter().enumerate() {
        let rendered = apply_template(arg, packet);
        validate_rendered_arg(rule_name, index, arg, &rendered)?;
        rendered_args.push(rendered);
    }

    validate_shape(&rendered_program, &rendered_args)?;

    let summary = format!(
        "program={:?} arg_count={}",
        rendered_program,
        rendered_args.len()
    );

    Ok(RenderedCommand {
        program: rendered_program,
        args: rendered_args,
        summary,
    })
}

fn validate_rendered_program(rule_name: &str, rendered_program: &str) -> ActionResult<()> {
    if rendered_program.trim().is_empty() {
        return Err(RuleActionError::InvalidCommandProgram {
            details: format!(
                "rule '{rule_name}' rendered program is empty after template application"
            ),
        });
    }
    if contains_control_chars(rendered_program) {
        return Err(RuleActionError::InvalidCommandProgram {
            details: format!("rule '{rule_name}' rendered program contains control characters"),
        });
    }
    if rendered_program.trim_start().starts_with('-') {
        return Err(RuleActionError::InvalidCommandProgram {
            details: format!("rule '{rule_name}' rendered program cannot start with '-'"),
        });
    }
    Ok(())
}

fn validate_rendered_arg(
    rule_name: &str,
    index: usize,
    template: &str,
    rendered: &str,
) -> ActionResult<()> {
    if !template.trim().starts_with('-') && rendered.trim().starts_with('-') {
        warn!(
            "rule '{}' command argument injection detected: template '{}' rendered to '{}' which looks like a flag. Blocking execution.",
            rule_name, template, rendered
        );
        telemetry::record_rule_action("command", "blocked_arg_injection");
        return Err(RuleActionError::ArgumentInjection {
            rule: rule_name.to_string(),
            arg: rendered.to_string(),
        });
    }
    if contains_control_chars(rendered) {
        telemetry::record_rule_action("command", "blocked_invalid_arg");
        return Err(RuleActionError::InvalidCommandArgument {
            index,
            details: format!("rule '{rule_name}' rendered argument contains control characters"),
        });
    }
    Ok(())
}

fn submit_command(
    rule_name: &str,
    rendered: RenderedCommand,
    timeout_duration: Duration,
    task_executor: &BoundedExecutor,
) -> std::result::Result<(), RuleError> {
    let rule_name_arc: Arc<str> = Arc::from(rule_name.to_string());
    let error_label = rendered.summary.clone();
    let task_rule_name = Arc::clone(&rule_name_arc);

    let spawn_result = task_executor.spawn_async(move || async move {
        run_spawned_command(task_rule_name, rendered, timeout_duration).await;
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

async fn run_spawned_command(
    rule_name: Arc<str>,
    rendered: RenderedCommand,
    timeout_duration: Duration,
) {
    let rule_name = rule_name.as_ref();
    trace!(
        "rule '{}' executing command: {}",
        rule_name,
        rendered.summary
    );
    telemetry::record_rule_action("command", "started");

    let child = tokio::process::Command::new(&rendered.program)
        .args(&rendered.args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn();

    match child {
        Ok(mut child) => match tokio::time::timeout(timeout_duration, child.wait()).await {
            Ok(Ok(status)) => {
                if status.success() {
                    telemetry::record_rule_action("command", "succeeded");
                    info!(
                        "rule '{}' command succeeded: {}",
                        rule_name, rendered.summary
                    );
                } else {
                    telemetry::record_rule_action("command", "failed");
                    warn!(
                        "rule '{}' command exited with status {}: {}",
                        rule_name, status, rendered.summary
                    );
                }
            }
            Ok(Err(err)) => {
                telemetry::record_rule_action("command", "wait_error");
                error!(
                    "rule '{}' failed to wait for command {}: {}",
                    rule_name, rendered.summary, err
                );
            }
            Err(_) => {
                telemetry::record_rule_action("command", "timeout");
                warn!(
                    "rule '{}' command timed out after {:?}: {}",
                    rule_name, timeout_duration, rendered.summary
                );
                // Child is killed on drop.
            }
        },
        Err(err) => {
            telemetry::record_rule_action("command", "spawn_error");
            error!(
                "rule '{}' failed to spawn command {}: {}",
                rule_name, rendered.summary, err
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;

    fn packet_context() -> PacketContext {
        PacketContext {
            description: "test".to_string(),
            source: Some("1.2.3.4".to_string()),
            destination: Some("5.6.7.8".to_string()),
            length: 100,
            timestamp: SystemTime::now(),
        }
    }

    #[test]
    fn validate_definition_accepts_defaults() {
        let args = vec!["-l".to_string(), "-a".to_string()];
        let timeout = validate_definition("/bin/ls", &args, None).expect("valid command");

        assert_eq!(timeout, RULE_COMMAND_TIMEOUT_SECONDS);
    }

    #[test]
    fn validate_definition_rejects_invalid_programs() {
        let empty = validate_definition("   ", &[], None);
        assert!(matches!(empty, Err(RuleActionError::MissingCommandProgram)));

        let control_chars = validate_definition("echo\n", &[], None);
        assert!(matches!(
            control_chars,
            Err(RuleActionError::InvalidCommandProgram { .. })
        ));

        let flag_like = validate_definition("-echo", &[], None);
        assert!(matches!(
            flag_like,
            Err(RuleActionError::InvalidCommandProgram { .. })
        ));
    }

    #[test]
    fn validate_definition_rejects_invalid_args() {
        let control_chars = validate_definition("echo", &["bad\n".to_string()], None);
        assert!(matches!(
            control_chars,
            Err(RuleActionError::InvalidCommandArgument { .. })
        ));

        let args = vec!["x".to_string(); RULE_COMMAND_MAX_ARGS + 1];
        let too_many_args = validate_definition("echo", &args, None);
        assert!(matches!(
            too_many_args,
            Err(RuleActionError::CommandShapeLimitExceeded { .. })
        ));
    }

    #[test]
    fn validate_definition_rejects_out_of_range_timeout() {
        let result = validate_definition("sleep", &[], Some(0));

        assert!(matches!(
            result,
            Err(RuleActionError::CommandTimeoutOutOfRange { .. })
        ));
    }

    #[test]
    fn render_invocation_applies_templates() {
        let args = vec!["{source}".to_string(), "{destination}".to_string()];
        let rendered =
            render_invocation("rule", Some(&packet_context()), "echo", &args).expect("render");

        assert_eq!(rendered.program, "echo");
        assert_eq!(
            rendered.args,
            vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()]
        );
        assert_eq!(rendered.summary, "program=\"echo\" arg_count=2");
    }

    #[test]
    fn render_invocation_rejects_empty_program() {
        let result = render_invocation("rule", Some(&packet_context()), "{source}", &[]);

        assert!(result.is_ok());

        let missing_program = render_invocation("rule", None, "   ", &[]);
        assert!(matches!(
            missing_program,
            Err(RuleActionError::InvalidCommandProgram { .. })
        ));
    }

    #[test]
    fn render_invocation_blocks_argument_injection() {
        let args = vec!["{source}".to_string()];
        let mut ctx = packet_context();
        ctx.source = Some("-rf".to_string());

        let result = render_invocation("rule", Some(&ctx), "echo", &args);

        assert!(matches!(
            result,
            Err(RuleActionError::ArgumentInjection { .. })
        ));
    }
}
