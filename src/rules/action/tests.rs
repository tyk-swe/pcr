// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::engine::request::PacketRequest;
use crate::rules::config::{
    RULE_EXECUTOR_QUEUE_CAPACITY, RULE_EXECUTOR_WORKERS, RULE_SEND_EXECUTOR_WORKERS,
};
use crate::rules::executor::{test_support, RuleSendExecutor};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

fn new_task_executor() -> Arc<BoundedExecutor> {
    Arc::new(
        BoundedExecutor::new(
            "rule-worker-test",
            RULE_EXECUTOR_WORKERS,
            RULE_EXECUTOR_WORKERS + RULE_EXECUTOR_QUEUE_CAPACITY,
        )
        .expect("create test task executor"),
    )
}

fn packet_context() -> PacketContext {
    PacketContext {
        description: "test".to_string(),
        source: Some("1.2.3.4".to_string()),
        destination: Some("5.6.7.8".to_string()),
        length: 100,
        timestamp: std::time::SystemTime::now(),
    }
}

fn log_action(message: &str) -> RuleAction {
    RuleAction::Log {
        level: RuleLogLevel::Info,
        message: message.to_string(),
    }
}

fn command_action(program: &str, args: &[&str], timeout_seconds: u64) -> RuleAction {
    RuleAction::Command(
        command::CommandAction::from_document(
            program.to_string(),
            args.iter().map(|arg| arg.to_string()).collect(),
            Some(timeout_seconds),
            false,
            Vec::new(),
            Some("/".to_string()),
        )
        .expect("valid command action"),
    )
}

fn enabled_command_action(program: &str, args: &[&str], timeout_seconds: u64) -> RuleAction {
    RuleAction::Command(
        command::CommandAction::from_document(
            program.to_string(),
            args.iter().map(|arg| arg.to_string()).collect(),
            Some(timeout_seconds),
            true,
            vec![program.to_string()],
            Some("/".to_string()),
        )
        .expect("valid command action"),
    )
}

fn log_document(message: &str, level: Option<RuleLogLevel>) -> RuleActionDocument {
    RuleActionDocument::Log {
        message: message.to_string(),
        level,
    }
}

fn command_document(
    program: &str,
    args: &[&str],
    timeout_seconds: Option<u64>,
) -> RuleActionDocument {
    RuleActionDocument::Command {
        program: program.to_string(),
        args: args.iter().map(|arg| arg.to_string()).collect(),
        timeout_seconds,
        enabled: false,
        allowed_programs: Vec::new(),
        working_dir: None,
    }
}

fn assert_log_action(action: RuleAction, expected_level: RuleLogLevel, expected_message: &str) {
    match action {
        RuleAction::Log { level, message } => {
            assert_eq!(level, expected_level);
            assert_eq!(message, expected_message);
        }
        other => panic!("wrong action type: {other:?}"),
    }
}

fn assert_command_action(
    action: RuleAction,
    expected_program: &str,
    expected_args: &[&str],
    expected_timeout: u64,
    expected_enabled: bool,
    expected_allowed_programs: &[&str],
    expected_working_dir: &str,
) {
    match action {
        RuleAction::Command(command_action) => {
            assert_eq!(command_action.program, expected_program);
            assert_eq!(command_action.args, expected_args);
            assert_eq!(command_action.timeout_seconds, expected_timeout);
            assert_eq!(command_action.enabled, expected_enabled);
            assert_eq!(command_action.allowed_programs, expected_allowed_programs);
            assert_eq!(command_action.working_dir, expected_working_dir);
        }
        other => panic!("wrong action type: {other:?}"),
    }
}

#[test]
fn send_action_without_sender_fails() {
    let template = RuleSendTemplate::new(PacketRequest::default());
    let action = RuleAction::Send(Box::new(template));
    let executor = new_task_executor();
    let result = action.execute("rule", None, None, executor.as_ref());
    assert!(result.is_err());
}

#[test]
fn log_action_applies_template_and_succeeds() {
    let action = log_action("src={source} dst={destination}");
    let ctx = packet_context();
    let executor = new_task_executor();
    let result = action.execute("rule", Some(&ctx), None, executor.as_ref());
    assert!(result.is_ok());
}

#[test]
fn log_action_with_empty_template_result_is_ignored() {
    let action = log_action("   ");
    let executor = new_task_executor();
    let result = action.execute("rule", None, None, executor.as_ref());
    assert!(result.is_ok());
}

#[test]
fn log_action_handles_missing_context() {
    let action = log_action("packet from {source}");
    let executor = new_task_executor();
    let result = action.execute("rule", None, None, executor.as_ref());
    assert!(result.is_ok());
}

#[test]
fn command_action_queues_successfully() {
    let _executor_guard = test_support::executor_lock();
    let action = enabled_command_action("/bin/true", &[], 5);
    let executor = new_task_executor();
    let result = action.execute("rule", None, None, executor.as_ref());
    assert!(result.is_ok());
}

#[test]
fn command_action_is_disabled_by_default() {
    let action = command_action("/bin/true", &[], 5);
    let executor = new_task_executor();
    let result = action.execute("rule", None, None, executor.as_ref());

    assert!(matches!(
        result,
        Err(RuleError::Action(RuleActionError::CommandDisabled { .. }))
    ));
}

#[test]
fn command_action_denies_program_not_in_allowlist() {
    let action = RuleAction::Command(
        command::CommandAction::from_document(
            "/bin/true".to_string(),
            Vec::new(),
            Some(5),
            true,
            vec!["/bin/false".to_string()],
            Some("/".to_string()),
        )
        .expect("valid command action"),
    );
    let executor = new_task_executor();
    let result = action.execute("rule", None, None, executor.as_ref());

    assert!(matches!(
        result,
        Err(RuleError::Action(
            RuleActionError::CommandProgramDenied { .. }
        ))
    ));
}

#[test]
fn command_action_denies_rendered_program_not_in_allowlist() {
    let mut ctx = packet_context();
    ctx.source = Some("/bin/true".to_string());
    let action = RuleAction::Command(
        command::CommandAction::from_document(
            "{source}".to_string(),
            Vec::new(),
            Some(5),
            true,
            vec!["/bin/false".to_string()],
            Some("/".to_string()),
        )
        .expect("valid command action"),
    );
    let executor = new_task_executor();
    let result = action.execute("rule", Some(&ctx), None, executor.as_ref());

    assert!(matches!(
        result,
        Err(RuleError::Action(RuleActionError::CommandProgramDenied {
            program,
            ..
        })) if program == "/bin/true"
    ));
}

#[test]
fn command_action_reports_queue_full_error() {
    let _executor_guard = test_support::executor_lock();

    let (ready_tx, ready_rx) = mpsc::channel();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let task_executor = new_task_executor();
    for _ in 0..RULE_EXECUTOR_WORKERS {
        let ready_tx = ready_tx.clone();
        let release = Arc::clone(&release);
        task_executor
            .spawn(move || {
                let _ = ready_tx.send(());
                let (lock, cvar) = &*release;
                let mut released = lock.lock().expect("lock poisoned");
                while !*released {
                    released = cvar.wait(released).expect("lock poisoned");
                }
            })
            .expect("spawn blocking worker task");
    }
    drop(ready_tx);
    for _ in 0..RULE_EXECUTOR_WORKERS {
        ready_rx.recv().expect("worker ready signal");
    }

    let (drain_tx, drain_rx) = mpsc::channel();
    for _ in 0..RULE_EXECUTOR_QUEUE_CAPACITY {
        let drain_tx = drain_tx.clone();
        task_executor
            .spawn(move || {
                let _ = drain_tx.send(());
            })
            .expect("enqueue drain task");
    }
    drop(drain_tx);

    let action = enabled_command_action("/bin/true", &[], 5);
    let result = action.execute("queue-full-rule", None, None, task_executor.as_ref());
    assert!(
        result.is_err(),
        "expected queue full error from command action"
    );

    let (lock, cvar) = &*release;
    let mut released = lock.lock().expect("lock poisoned");
    *released = true;
    cvar.notify_all();
    drop(released);

    for _ in 0..RULE_EXECUTOR_QUEUE_CAPACITY {
        drain_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("drain task completion");
    }
}

#[test]
fn long_running_send_actions_do_not_starve_command_queue() {
    let _executor_guard = test_support::executor_lock();

    let started = Arc::new(AtomicUsize::new(0));
    let release = Arc::new((Mutex::new(false), Condvar::new()));

    let _hook_guard = test_support::send_hook_guard(Some({
        let started = Arc::clone(&started);
        let release = Arc::clone(&release);
        Arc::new(move |_, _| {
            started.fetch_add(1, Ordering::SeqCst);
            let (lock, cvar) = &*release;
            let mut released = lock.lock().expect("lock poisoned");
            while !*released {
                released = cvar.wait(released).expect("lock poisoned");
            }
            std::thread::sleep(Duration::from_millis(10));
            Ok(())
        })
    }));

    let executor = RuleSendExecutor::new().expect("create send executor");
    let template = RuleSendTemplate::new(PacketRequest::default());

    for _ in 0..RULE_SEND_EXECUTOR_WORKERS {
        executor
            .dispatch("blocking", &template, None)
            .expect("enqueue blocking send task");
    }

    let deadline = Instant::now() + Duration::from_secs(2);
    while started.load(Ordering::SeqCst) < RULE_SEND_EXECUTOR_WORKERS && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        started.load(Ordering::SeqCst) > 0,
        "send tasks failed to start"
    );

    let command_action = enabled_command_action("/bin/true", &[], 5);

    let task_executor = new_task_executor();
    let result = command_action.execute("command", None, Some(&executor), task_executor.as_ref());
    assert!(result.is_ok(), "command actions should queue successfully");

    let (lock, cvar) = &*release;
    let mut released = lock.lock().expect("lock poisoned");
    *released = true;
    cvar.notify_all();
    drop(released);
}

#[test]
fn try_from_rule_action_document_log_variants() {
    for (level, expected_level) in [
        (Some(RuleLogLevel::Warn), RuleLogLevel::Warn),
        (None, RuleLogLevel::Info),
    ] {
        let action = log_document("test log", level)
            .try_into()
            .expect("valid log action");
        assert_log_action(action, expected_level, "test log");
    }
}

#[test]
fn try_from_rule_action_document_log_empty_message() {
    let doc = log_document("   ", None);
    let result: Result<RuleAction> = doc.try_into();
    assert!(result.is_err());
    match result.unwrap_err() {
        RuleError::Action(RuleActionError::EmptyLogMessage) => {}
        err => panic!("unexpected error: {:?}", err),
    }
}

#[test]
fn try_from_rule_action_document_command_variants() {
    for (program, args, timeout, expected_timeout) in [
        ("/bin/ls", &["-l", "-a"][..], Some(10), 10),
        (
            "ls",
            &[][..],
            None,
            crate::rules::config::RULE_COMMAND_TIMEOUT_SECONDS,
        ),
    ] {
        let action = command_document(program, args, timeout)
            .try_into()
            .expect("valid command action");
        assert_command_action(action, program, args, expected_timeout, false, &[], "/");
    }
}

#[test]
fn try_from_rule_action_document_command_accepts_explicit_policy_fields() {
    let doc: RuleActionDocument = crate::rules::yaml::from_str(
        r#"
type: command
program: "/bin/true"
enabled: true
allowed_programs:
  - "/bin/true"
working_dir: "/tmp"
"#,
    )
    .expect("command action should deserialize");

    let action = doc.try_into().expect("valid command action");

    assert_command_action(action, "/bin/true", &[], 5, true, &["/bin/true"], "/tmp");
}

#[test]
fn try_from_rule_action_document_rejects_enabled_command_without_allowlist() {
    let doc: RuleActionDocument = crate::rules::yaml::from_str(
        r#"
type: command
program: "/bin/true"
enabled: true
"#,
    )
    .expect("command action should deserialize");

    let result: Result<RuleAction> = doc.try_into();

    assert!(matches!(
        result,
        Err(RuleError::Action(RuleActionError::MissingCommandAllowlist))
    ));
}

#[test]
fn try_from_rule_action_document_rejects_enabled_relative_literal_program() {
    let doc: RuleActionDocument = crate::rules::yaml::from_str(
        r#"
type: command
program: "true"
enabled: true
allowed_programs:
  - "/bin/true"
"#,
    )
    .expect("command action should deserialize");

    let result: Result<RuleAction> = doc.try_into();

    assert!(matches!(
        result,
        Err(RuleError::Action(
            RuleActionError::InvalidCommandProgram { .. }
        ))
    ));
}

#[test]
fn try_from_rule_action_document_rejects_relative_allowed_program() {
    let doc: RuleActionDocument = crate::rules::yaml::from_str(
        r#"
type: command
program: "true"
enabled: true
allowed_programs:
  - "true"
"#,
    )
    .expect("command action should deserialize");

    let result: Result<RuleAction> = doc.try_into();

    assert!(matches!(
        result,
        Err(RuleError::Action(
            RuleActionError::InvalidCommandAllowlistEntry { .. }
        ))
    ));
}

#[test]
fn try_from_rule_action_document_rejects_relative_working_dir() {
    let doc: RuleActionDocument = crate::rules::yaml::from_str(
        r#"
type: command
program: "/bin/true"
working_dir: "relative"
"#,
    )
    .expect("command action should deserialize");

    let result: Result<RuleAction> = doc.try_into();

    assert!(matches!(
        result,
        Err(RuleError::Action(
            RuleActionError::InvalidCommandWorkingDir { .. }
        ))
    ));
}

#[test]
fn try_from_rule_action_document_send() {
    let doc = RuleActionDocument::Send {
        legacy_options: None,
        request: Box::new(PacketRequest::default()),
    };
    let action: RuleAction = doc.try_into().expect("valid send action");
    match action {
        RuleAction::Send(_) => {} // OK
        _ => panic!("wrong action type"),
    }
}

#[test]
fn send_action_rejects_legacy_options_wrapper() {
    let doc: RuleActionDocument = crate::rules::yaml::from_str(
        r#"
type: send
options:
  destination:
    destination: "127.0.0.1"
"#,
    )
    .expect("legacy send action should deserialize for validation");

    let result: Result<RuleAction> = doc.try_into();
    assert!(matches!(
        result,
        Err(RuleError::Action(RuleActionError::LegacySendOptionsWrapper))
    ));
}
