// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::Path;
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
                // Child is killed on drop.
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
    use std::fs;
    use std::time::SystemTime;

    use super::*;
    use serial_test::serial;

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
        let timeout =
            validate_definition("/bin/ls", &args, None, false, &[], "/").expect("valid command");

        assert_eq!(timeout, RULE_COMMAND_TIMEOUT_SECONDS);
    }

    #[test]
    fn validate_definition_rejects_invalid_programs() {
        let empty = validate_definition("   ", &[], None, false, &[], "/");
        assert!(matches!(empty, Err(RuleActionError::MissingCommandProgram)));

        let control_chars = validate_definition("echo\n", &[], None, false, &[], "/");
        assert!(matches!(
            control_chars,
            Err(RuleActionError::InvalidCommandProgram { .. })
        ));

        let flag_like = validate_definition("-echo", &[], None, false, &[], "/");
        assert!(matches!(
            flag_like,
            Err(RuleActionError::InvalidCommandProgram { .. })
        ));
    }

    #[test]
    fn validate_definition_rejects_invalid_args() {
        let control_chars =
            validate_definition("echo", &["bad\n".to_string()], None, false, &[], "/");
        assert!(matches!(
            control_chars,
            Err(RuleActionError::InvalidCommandArgument { .. })
        ));

        let args = vec!["x".to_string(); RULE_COMMAND_MAX_ARGS + 1];
        let too_many_args = validate_definition("echo", &args, None, false, &[], "/");
        assert!(matches!(
            too_many_args,
            Err(RuleActionError::CommandShapeLimitExceeded { .. })
        ));
    }

    #[test]
    fn validate_definition_rejects_out_of_range_timeout() {
        let result = validate_definition("sleep", &[], Some(0), false, &[], "/");

        assert!(matches!(
            result,
            Err(RuleActionError::CommandTimeoutOutOfRange { .. })
        ));
    }

    #[test]
    fn validate_definition_accepts_enabled_absolute_allowlist() {
        let allowed = vec!["/bin/true".to_string()];

        let result = validate_definition("/bin/true", &[], Some(1), true, &allowed, "/")
            .expect("valid enabled command");

        assert_eq!(result, 1);
    }

    #[test]
    fn validate_definition_rejects_enabled_relative_literal_program() {
        let allowed = vec!["/bin/true".to_string()];

        let result = validate_definition("true", &[], Some(1), true, &allowed, "/");

        assert!(matches!(
            result,
            Err(RuleActionError::InvalidCommandProgram { .. })
        ));
    }

    #[test]
    fn validate_definition_accepts_enabled_templated_program() {
        let allowed = vec!["/bin/true".to_string()];

        let result = validate_definition("{source}", &[], Some(1), true, &allowed, "/")
            .expect("templated program may render to an allowlisted absolute path");

        assert_eq!(result, 1);
    }

    #[test]
    fn validate_definition_rejects_enabled_without_allowlist() {
        let result = validate_definition("/bin/true", &[], Some(1), true, &[], "/");

        assert!(matches!(
            result,
            Err(RuleActionError::MissingCommandAllowlist)
        ));
    }

    #[test]
    fn validate_definition_rejects_relative_allowlist_path() {
        let allowed = vec!["true".to_string()];

        let result = validate_definition("true", &[], Some(1), true, &allowed, "/");

        assert!(matches!(
            result,
            Err(RuleActionError::InvalidCommandAllowlistEntry { .. })
        ));
    }

    #[test]
    fn validate_definition_rejects_relative_working_dir() {
        let result = validate_definition("/bin/true", &[], Some(1), false, &[], "relative");

        assert!(matches!(
            result,
            Err(RuleActionError::InvalidCommandWorkingDir { .. })
        ));
    }

    #[test]
    fn render_invocation_applies_templates() {
        let args = vec!["{source}".to_string(), "{destination}".to_string()];
        let rendered =
            render_invocation("rule", Some(&packet_context()), "echo", &args, "/").expect("render");

        assert_eq!(rendered.program, "echo");
        assert_eq!(
            rendered.args,
            vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()]
        );
        assert_eq!(
            rendered.summary,
            "program=\"echo\" arg_count=2 working_dir=\"/\""
        );
    }

    #[test]
    fn render_invocation_rejects_empty_program() {
        let result = render_invocation("rule", Some(&packet_context()), "{source}", &[], "/");

        assert!(result.is_ok());

        let missing_program = render_invocation("rule", None, "   ", &[], "/");
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

        let result = render_invocation("rule", Some(&ctx), "echo", &args, "/");

        assert!(matches!(
            result,
            Err(RuleActionError::ArgumentInjection { .. })
        ));
    }

    #[tokio::test]
    async fn run_spawned_command_reports_timeout() {
        let rendered = RenderedCommand {
            program: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), "sleep 5".to_string()],
            working_dir: "/".to_string(),
            summary: "timeout test".to_string(),
        };

        let outcome =
            run_spawned_command(Arc::from("rule"), rendered, Duration::from_millis(20)).await;

        assert_eq!(outcome, CommandRunOutcome::Timeout);
    }

    #[tokio::test]
    #[serial]
    async fn run_spawned_command_clears_environment_and_uses_working_dir() {
        const TEST_ENV: &str = "PCR_RULE_COMMAND_ENV_TEST";
        std::env::set_var(TEST_ENV, "leaked");

        let dir = tempfile::tempdir().expect("create temp working dir");
        let script = format!(
            "pwd > pwd.txt\nif [ -z \"${TEST_ENV}\" ]; then echo cleared > env.txt; else echo leaked > env.txt; fi"
        );
        let rendered = RenderedCommand {
            program: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), script],
            working_dir: dir.path().to_string_lossy().into_owned(),
            summary: "environment test".to_string(),
        };

        let outcome =
            run_spawned_command(Arc::from("rule"), rendered, Duration::from_secs(2)).await;
        std::env::remove_var(TEST_ENV);

        assert_eq!(outcome, CommandRunOutcome::Success);
        let pwd = fs::read_to_string(dir.path().join("pwd.txt")).expect("read pwd output");
        assert_eq!(pwd.trim(), dir.path().to_string_lossy());
        let env = fs::read_to_string(dir.path().join("env.txt")).expect("read env output");
        assert_eq!(env.trim(), "cleared");
    }
}
