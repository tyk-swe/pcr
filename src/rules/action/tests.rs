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
    let action = RuleAction::Log {
        level: RuleLogLevel::Info,
        message: "src={source} dst={destination}".to_string(),
    };
    let ctx = PacketContext {
        description: "test".to_string(),
        source: Some("1.2.3.4".to_string()),
        destination: Some("5.6.7.8".to_string()),
        length: 100,
        timestamp: std::time::SystemTime::now(),
    };
    let executor = new_task_executor();
    let result = action.execute("rule", Some(&ctx), None, executor.as_ref());
    assert!(result.is_ok());
}

#[test]
fn log_action_with_empty_template_result_is_ignored() {
    let action = RuleAction::Log {
        level: RuleLogLevel::Info,
        message: "   ".to_string(),
    };
    let executor = new_task_executor();
    let result = action.execute("rule", None, None, executor.as_ref());
    assert!(result.is_ok());
}

#[test]
fn log_action_handles_missing_context() {
    let action = RuleAction::Log {
        level: RuleLogLevel::Info,
        message: "packet from {source}".to_string(),
    };
    let executor = new_task_executor();
    let result = action.execute("rule", None, None, executor.as_ref());
    assert!(result.is_ok());
}

#[test]
fn command_action_queues_successfully() {
    let _executor_guard = test_support::executor_lock();
    let action = RuleAction::Command {
        program: "true".to_string(),
        args: Vec::new(),
        timeout_seconds: 5,
    };
    let executor = new_task_executor();
    let result = action.execute("rule", None, None, executor.as_ref());
    assert!(result.is_ok());
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

    let action = RuleAction::Command {
        program: "true".to_string(),
        args: Vec::new(),
        timeout_seconds: 5,
    };
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

    let command_action = RuleAction::Command {
        program: "true".to_string(),
        args: Vec::new(),
        timeout_seconds: 5,
    };

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
fn try_from_rule_action_document_log() {
    let doc = RuleActionDocument::Log {
        message: "test log".to_string(),
        level: Some(RuleLogLevel::Warn),
    };
    let action: RuleAction = doc.try_into().expect("valid log action");
    match action {
        RuleAction::Log { level, message } => {
            assert_eq!(level, RuleLogLevel::Warn);
            assert_eq!(message, "test log");
        }
        _ => panic!("wrong action type"),
    }
}

#[test]
fn try_from_rule_action_document_log_default_level() {
    let doc = RuleActionDocument::Log {
        message: "test log".to_string(),
        level: None,
    };
    let action: RuleAction = doc.try_into().expect("valid log action");
    match action {
        RuleAction::Log { level, message } => {
            assert_eq!(level, RuleLogLevel::Info); // Default is Info
            assert_eq!(message, "test log");
        }
        _ => panic!("wrong action type"),
    }
}

#[test]
fn try_from_rule_action_document_log_empty_message() {
    let doc = RuleActionDocument::Log {
        message: "   ".to_string(),
        level: None,
    };
    let result: Result<RuleAction> = doc.try_into();
    assert!(result.is_err());
    match result.unwrap_err() {
        RuleError::Action(RuleActionError::EmptyLogMessage) => {}
        err => panic!("unexpected error: {:?}", err),
    }
}

#[test]
fn try_from_rule_action_document_command() {
    let doc = RuleActionDocument::Command {
        program: "/bin/ls".to_string(),
        args: vec!["-l".to_string(), "-a".to_string()],
        timeout_seconds: Some(10),
    };
    let action: RuleAction = doc.try_into().expect("valid command action");
    match action {
        RuleAction::Command {
            program,
            args,
            timeout_seconds,
        } => {
            assert_eq!(program, "/bin/ls");
            assert_eq!(args, vec!["-l", "-a"]);
            assert_eq!(timeout_seconds, 10);
        }
        _ => panic!("wrong action type"),
    }
}

#[test]
fn try_from_rule_action_document_command_defaults() {
    let doc = RuleActionDocument::Command {
        program: "ls".to_string(),
        args: Vec::new(),
        timeout_seconds: None,
    };
    let action: RuleAction = doc.try_into().expect("valid command action");
    match action {
        RuleAction::Command {
            program,
            args,
            timeout_seconds,
        } => {
            assert_eq!(program, "ls");
            assert!(args.is_empty());
            assert_eq!(
                timeout_seconds,
                crate::rules::config::RULE_COMMAND_TIMEOUT_SECONDS
            );
        }
        _ => panic!("wrong action type"),
    }
}

#[test]
fn try_from_rule_action_document_command_empty_program() {
    let doc = RuleActionDocument::Command {
        program: "   ".to_string(),
        args: Vec::new(),
        timeout_seconds: None,
    };
    let result: Result<RuleAction> = doc.try_into();
    assert!(result.is_err());
    match result.unwrap_err() {
        RuleError::Action(RuleActionError::MissingCommandProgram) => {}
        err => panic!("unexpected error: {:?}", err),
    }
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

#[test]
fn command_action_handles_template_substitution() {
    let _executor_guard = test_support::executor_lock();
    let action = RuleAction::Command {
        program: "echo".to_string(),
        args: vec!["{source}".to_string(), "{destination}".to_string()],
        timeout_seconds: 5,
    };
    let ctx = PacketContext {
        description: "test".to_string(),
        source: Some("1.2.3.4".to_string()),
        destination: Some("5.6.7.8".to_string()),
        length: 100,
        timestamp: std::time::SystemTime::now(),
    };
    let executor = new_task_executor();
    // Since we cannot easily intercept the command execution in unit tests without mocking Process,
    // we can at least ensure it executes without error.
    let result = action.execute("rule", Some(&ctx), None, executor.as_ref());
    assert!(result.is_ok());
}

#[test]
fn command_action_rejects_empty_rendered_program() {
    let _executor_guard = test_support::executor_lock();
    let action = RuleAction::Command {
        program: "   ".to_string(),
        args: Vec::new(),
        timeout_seconds: 5,
    };
    let ctx = PacketContext {
        description: "test".to_string(),
        source: None,
        destination: Some("5.6.7.8".to_string()),
        length: 100,
        timestamp: std::time::SystemTime::now(),
    };
    let executor = new_task_executor();
    let result = action.execute("rule", Some(&ctx), None, executor.as_ref());
    assert!(matches!(
        result,
        Err(RuleError::Action(
            RuleActionError::InvalidCommandProgram { .. }
        ))
    ));
}

#[test]
fn try_from_rule_action_document_command_timeout_default() {
    let doc = RuleActionDocument::Command {
        program: "sleep".to_string(),
        args: Vec::new(),
        timeout_seconds: None,
    };
    let action: RuleAction = doc.try_into().expect("valid command action");
    match action {
        RuleAction::Command {
            timeout_seconds, ..
        } => {
            assert_eq!(
                timeout_seconds,
                crate::rules::config::RULE_COMMAND_TIMEOUT_SECONDS
            );
        }
        _ => panic!("wrong action type"),
    }
}

#[test]
fn try_from_rule_action_document_command_rejects_zero_timeout() {
    let doc = RuleActionDocument::Command {
        program: "sleep".to_string(),
        args: Vec::new(),
        timeout_seconds: Some(0),
    };
    let result: Result<RuleAction> = doc.try_into();
    assert!(matches!(
        result,
        Err(RuleError::Action(
            RuleActionError::CommandTimeoutOutOfRange { .. }
        ))
    ));
}

#[test]
fn try_from_rule_action_document_command_rejects_too_many_args() {
    let doc = RuleActionDocument::Command {
        program: "echo".to_string(),
        args: vec!["x".to_string(); crate::rules::config::RULE_COMMAND_MAX_ARGS + 1],
        timeout_seconds: Some(5),
    };
    let result: Result<RuleAction> = doc.try_into();
    assert!(matches!(
        result,
        Err(RuleError::Action(
            RuleActionError::CommandShapeLimitExceeded { .. }
        ))
    ));
}

#[test]
fn try_from_rule_action_document_command_rejects_control_chars() {
    let doc = RuleActionDocument::Command {
        program: "echo\n".to_string(),
        args: vec!["ok".to_string()],
        timeout_seconds: Some(5),
    };
    let result: Result<RuleAction> = doc.try_into();
    assert!(matches!(
        result,
        Err(RuleError::Action(
            RuleActionError::InvalidCommandProgram { .. }
        ))
    ));
}
