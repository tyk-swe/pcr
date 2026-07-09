// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use log::{error, info, trace, warn};
use tokio::process::Child;

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

const COMMAND_REAP_GRACE: Duration = Duration::from_millis(500);

struct RenderedCommand {
    program: String,
    args: Vec<String>,
    working_dir: String,
    summary: String,
}

#[derive(Debug, Clone)]
pub(crate) struct CommandAction {
    pub(super) program: String,
    pub(super) args: Vec<String>,
    pub(super) timeout_seconds: u64,
    pub(super) enabled: bool,
    pub(super) allowed_programs: Vec<String>,
    pub(super) working_dir: String,
}

impl CommandAction {
    pub(super) fn from_document(
        program: String,
        args: Vec<String>,
        timeout_seconds: Option<u64>,
        enabled: bool,
        allowed_programs: Vec<String>,
        working_dir: Option<String>,
    ) -> ActionResult<Self> {
        let working_dir = working_dir.unwrap_or_else(|| "/".to_string());
        let timeout_seconds = validate_definition(
            &program,
            &args,
            timeout_seconds,
            enabled,
            &allowed_programs,
            &working_dir,
        )?;

        Ok(Self {
            program,
            args,
            timeout_seconds,
            enabled,
            allowed_programs,
            working_dir,
        })
    }

    pub(super) fn execute(
        &self,
        rule_name: &str,
        packet: Option<&PacketContext>,
        task_executor: &BoundedExecutor,
    ) -> std::result::Result<(), RuleError> {
        if !self.enabled {
            warn!("rule '{}' command action blocked: disabled", rule_name);
            telemetry::record_rule_action("command", "disabled");
            return Err(RuleActionError::CommandDisabled {
                rule: rule_name.to_string(),
            }
            .into());
        }

        let rendered = render_invocation(
            rule_name,
            packet,
            &self.program,
            &self.args,
            &self.working_dir,
        )?;
        if !self
            .allowed_programs
            .iter()
            .any(|allowed| allowed == &rendered.program)
        {
            warn!(
                "rule '{}' command action denied: program {:?} is not in the allowlist",
                rule_name, rendered.program
            );
            telemetry::record_rule_action("command", "denied");
            return Err(RuleActionError::CommandProgramDenied {
                rule: rule_name.to_string(),
                program: rendered.program,
            }
            .into());
        }

        submit_command(
            rule_name,
            rendered,
            Duration::from_secs(self.timeout_seconds),
            task_executor,
        )
    }
}

fn validate_definition(
    program: &str,
    args: &[String],
    timeout_seconds: Option<u64>,
    enabled: bool,
    allowed_programs: &[String],
    working_dir: &str,
) -> ActionResult<u64> {
    validate_program(program)?;
    validate_definition_args(args)?;
    validate_allowed_programs(enabled, allowed_programs)?;
    validate_enabled_program(program, enabled)?;
    validate_working_dir(working_dir)?;
    validate_shape(program, args)?;
    timeout_or_default(timeout_seconds)
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

fn validate_enabled_program(program: &str, enabled: bool) -> ActionResult<()> {
    if enabled && !is_templated(program) && !Path::new(program).is_absolute() {
        return Err(RuleActionError::InvalidCommandProgram {
            details: format!(
                "enabled command program must be absolute unless templated: {program}"
            ),
        });
    }
    Ok(())
}

fn is_templated(input: &str) -> bool {
    apply_template(input, None) != input
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

fn validate_allowed_programs(enabled: bool, allowed_programs: &[String]) -> ActionResult<()> {
    if enabled && allowed_programs.is_empty() {
        return Err(RuleActionError::MissingCommandAllowlist);
    }

    for (index, program) in allowed_programs.iter().enumerate() {
        if program.trim().is_empty() {
            return Err(RuleActionError::InvalidCommandAllowlistEntry {
                index,
                details: "allowed program is empty".to_string(),
            });
        }
        if contains_control_chars(program) {
            return Err(RuleActionError::InvalidCommandAllowlistEntry {
                index,
                details: "allowed program contains control characters".to_string(),
            });
        }
        if !Path::new(program).is_absolute() {
            return Err(RuleActionError::InvalidCommandAllowlistEntry {
                index,
                details: format!("allowed program must be absolute: {program}"),
            });
        }
        if program.len() > RULE_COMMAND_MAX_PROGRAM_LENGTH {
            return Err(RuleActionError::CommandShapeLimitExceeded {
                details: format!(
                    "allowed program {index} length {} exceeds maximum {}",
                    program.len(),
                    RULE_COMMAND_MAX_PROGRAM_LENGTH
                ),
            });
        }
    }

    Ok(())
}

fn validate_working_dir(working_dir: &str) -> ActionResult<()> {
    if working_dir.trim().is_empty() {
        return Err(RuleActionError::InvalidCommandWorkingDir {
            details: "working directory is empty".to_string(),
        });
    }
    if contains_control_chars(working_dir) {
        return Err(RuleActionError::InvalidCommandWorkingDir {
            details: "working directory contains control characters".to_string(),
        });
    }
    if !Path::new(working_dir).is_absolute() {
        return Err(RuleActionError::InvalidCommandWorkingDir {
            details: format!("working directory must be absolute: {working_dir}"),
        });
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
    working_dir: &str,
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
        "program={:?} arg_count={} working_dir={:?}",
        rendered_program,
        rendered_args.len(),
        working_dir
    );

    Ok(RenderedCommand {
        program: rendered_program,
        args: rendered_args,
        working_dir: working_dir.to_string(),
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
            info!(
                "rule '{}' command action queued for asynchronous execution ({})",
                rule_name_arc.as_ref(),
                error_label
            );
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
) -> CommandRunOutcome {
    let rule_name = rule_name.as_ref();
    trace!(
        "rule '{}' executing command: {}",
        rule_name,
        rendered.summary
    );
    telemetry::record_rule_action("command", "spawn");

    let mut command = tokio::process::Command::new(&rendered.program);
    command
        .args(&rendered.args)
        .current_dir(&rendered.working_dir)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let child = command.spawn();

    match child {
        Ok(mut child) => match tokio::time::timeout(timeout_duration, child.wait()).await {
            Ok(Ok(status)) => {
                if status.success() {
                    telemetry::record_rule_action("command", "success");
                    info!(
                        "rule '{}' command succeeded: {}",
                        rule_name, rendered.summary
                    );
                    CommandRunOutcome::Success
                } else {
                    telemetry::record_rule_action("command", "failure");
                    warn!(
                        "rule '{}' command exited with status {}: {}",
                        rule_name, status, rendered.summary
                    );
                    CommandRunOutcome::Failure
                }
            }
            Ok(Err(err)) => {
                telemetry::record_rule_action("command", "wait_error");
                error!(
                    "rule '{}' failed to wait for command {}: {}",
                    rule_name, rendered.summary, err
                );
                CommandRunOutcome::WaitError
            }
            Err(_) => {
                telemetry::record_rule_action("command", "timeout");
                warn!(
                    "rule '{}' command timed out after {:?}: {}",
                    rule_name, timeout_duration, rendered.summary
                );
                kill_and_reap_timed_out_child(rule_name, &rendered.summary, &mut child).await;
                CommandRunOutcome::Timeout
            }
        },
        Err(err) => {
            telemetry::record_rule_action("command", "spawn_error");
            error!(
                "rule '{}' failed to spawn command {}: {}",
                rule_name, rendered.summary, err
            );
            CommandRunOutcome::SpawnError
        }
    }
}

async fn kill_and_reap_timed_out_child(rule_name: &str, summary: &str, child: &mut Child) {
    match child.start_kill() {
        Ok(()) => {
            telemetry::record_rule_action("command", "timeout_kill_sent");
            trace!(
                "rule '{}' sent kill to timed-out command: {}",
                rule_name,
                summary
            );
        }
        Err(err) => {
            telemetry::record_rule_action("command", "timeout_kill_error");
            warn!(
                "rule '{}' failed to kill timed-out command {}: {}",
                rule_name, summary, err
            );
        }
    }

    match tokio::time::timeout(COMMAND_REAP_GRACE, child.wait()).await {
        Ok(Ok(status)) => {
            telemetry::record_rule_action("command", "timeout_reaped");
            trace!(
                "rule '{}' reaped timed-out command with status {}: {}",
                rule_name,
                status,
                summary
            );
        }
        Ok(Err(err)) => {
            telemetry::record_rule_action("command", "timeout_reap_error");
            warn!(
                "rule '{}' failed to reap timed-out command {}: {}",
                rule_name, summary, err
            );
        }
        Err(_) => {
            telemetry::record_rule_action("command", "timeout_reap_timeout");
            warn!(
                "rule '{}' timed-out command did not exit within {:?}: {}",
                rule_name, COMMAND_REAP_GRACE, summary
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandRunOutcome {
    Success,
    Failure,
    Timeout,
    SpawnError,
    WaitError,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use std::time::SystemTime;
    use tokio::runtime::Handle;

    fn packet_with_source(source: &str) -> PacketContext {
        PacketContext {
            description: "packet".to_string(),
            source: Some(source.to_string()),
            destination: Some("198.51.100.20".to_string()),
            length: 42,
            timestamp: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn command_action_from_document_accepts_disabled_relative_program() {
        let action = CommandAction::from_document(
            "echo".to_string(),
            vec!["hello".to_string()],
            None,
            false,
            vec![],
            None,
        )
        .unwrap();

        assert_eq!(action.program, "echo");
        assert_eq!(action.timeout_seconds, RULE_COMMAND_TIMEOUT_SECONDS);
        assert!(!action.enabled);
        assert_eq!(action.working_dir, "/");
    }

    #[test]
    fn command_action_from_document_requires_program() {
        let err = CommandAction::from_document(" ".to_string(), vec![], None, false, vec![], None)
            .unwrap_err();

        assert!(matches!(err, RuleActionError::MissingCommandProgram));
    }

    #[test]
    fn command_action_from_document_rejects_enabled_command_without_allowlist() {
        let err =
            CommandAction::from_document("/bin/echo".to_string(), vec![], None, true, vec![], None)
                .unwrap_err();

        assert!(matches!(err, RuleActionError::MissingCommandAllowlist));
    }

    #[test]
    fn command_action_from_document_rejects_relative_enabled_program() {
        let err = CommandAction::from_document(
            "echo".to_string(),
            vec![],
            None,
            true,
            vec!["/bin/echo".to_string()],
            None,
        )
        .unwrap_err();

        assert!(matches!(err, RuleActionError::InvalidCommandProgram { .. }));
    }

    #[test]
    fn command_action_from_document_rejects_invalid_allowlist_and_working_dir() {
        let allowlist_err = CommandAction::from_document(
            "/bin/echo".to_string(),
            vec![],
            None,
            true,
            vec!["echo".to_string()],
            None,
        )
        .unwrap_err();
        let cwd_err = CommandAction::from_document(
            "echo".to_string(),
            vec![],
            None,
            false,
            vec![],
            Some("relative".to_string()),
        )
        .unwrap_err();

        assert!(matches!(
            allowlist_err,
            RuleActionError::InvalidCommandAllowlistEntry { index: 0, .. }
        ));
        assert!(matches!(
            cwd_err,
            RuleActionError::InvalidCommandWorkingDir { .. }
        ));
    }

    #[test]
    fn command_action_from_document_rejects_timeout_out_of_range() {
        let err = CommandAction::from_document(
            "echo".to_string(),
            vec![],
            Some(RULE_COMMAND_TIMEOUT_MAX_SECONDS + 1),
            false,
            vec![],
            None,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            RuleActionError::CommandTimeoutOutOfRange { .. }
        ));
    }

    #[test]
    fn command_action_from_document_rejects_shape_limits() {
        let err = CommandAction::from_document(
            "e".repeat(RULE_COMMAND_MAX_PROGRAM_LENGTH + 1),
            vec![],
            None,
            false,
            vec![],
            None,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            RuleActionError::CommandShapeLimitExceeded { .. }
        ));
    }

    #[test]
    fn render_invocation_applies_templates() {
        let packet = packet_with_source("192.0.2.10");
        let rendered = render_invocation(
            "rule",
            Some(&packet),
            "/bin/echo",
            &["source={source}".to_string()],
            "/",
        )
        .unwrap();

        assert_eq!(rendered.program, "/bin/echo");
        assert_eq!(rendered.args, vec!["source=192.0.2.10"]);
        assert_eq!(rendered.working_dir, "/");
    }

    #[test]
    fn render_invocation_blocks_argument_injection_from_templates() {
        let packet = packet_with_source("--danger");
        let result = render_invocation(
            "rule",
            Some(&packet),
            "/bin/echo",
            &["{source}".to_string()],
            "/",
        );

        assert!(matches!(
            result,
            Err(RuleActionError::ArgumentInjection {
                rule,
                arg
            }) if rule == "rule" && arg == "--danger"
        ));
    }

    #[test]
    fn render_invocation_allows_flag_template_that_starts_as_flag() {
        let packet = packet_with_source("danger");
        let rendered = render_invocation(
            "rule",
            Some(&packet),
            "/bin/echo",
            &["--value={source}".to_string()],
            "/",
        )
        .unwrap();

        assert_eq!(rendered.args, vec!["--value=danger"]);
    }

    #[tokio::test]
    async fn command_action_execute_returns_after_queueing_before_child_completion() {
        let executor = BoundedExecutor::new_with_handle(Handle::current(), 1, 2).unwrap();
        let action = CommandAction::from_document(
            "/bin/sh".to_string(),
            vec!["-c".to_string(), "sleep 1".to_string()],
            Some(1),
            true,
            vec!["/bin/sh".to_string()],
            None,
        )
        .unwrap();

        let started = Instant::now();
        action.execute("queued-command", None, &executor).unwrap();

        assert!(
            started.elapsed() < Duration::from_millis(250),
            "command action should return after queueing, not after child completion"
        );
    }

    #[tokio::test]
    async fn timed_out_command_is_explicitly_killed_and_reaped() {
        let rendered = RenderedCommand {
            program: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), "sleep 5".to_string()],
            working_dir: "/".to_string(),
            summary: "test timed-out command".to_string(),
        };

        let outcome = run_spawned_command(
            Arc::<str>::from("timeout-command"),
            rendered,
            Duration::from_millis(10),
        )
        .await;

        assert_eq!(outcome, CommandRunOutcome::Timeout);
    }
}
