// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::rules::RuleSendExecutor;
use std::io::Write;
use tempfile::NamedTempFile;

fn empty_engine_config() -> EngineConfig {
    EngineConfig {
        output_format: None,
        prometheus_bind: None,
        rule_workers: None,
        rule_queue: None,
        send_workers: None,
        send_queue: None,
        traffic_policy: crate::engine::policy::TrafficPolicy::default(),
        dry_run: false,
    }
}

fn rule_engine() -> RuleEngine {
    let mut rules = RuleEngine::new().expect("rule engine initialisation");
    rules.configure_sender(RuleSendExecutor::new().expect("rule send executor initialisation"));
    rules
}

#[tokio::test]
async fn handle_command_reports_status_and_shutdown() {
    let mut state = DaemonState::new();
    let mut rules = rule_engine();
    let config = empty_engine_config();
    let output = OutputController::new(None);

    let (tx, rx) = oneshot::channel();
    let exit = handle_command(
        DaemonCommand::Status { respond_to: tx },
        &mut state,
        &mut rules,
        &config,
        &output,
    )
    .await
    .unwrap();
    assert!(!exit);
    let message = rx.await.unwrap().unwrap();
    assert_eq!(message, "rules=0 receive_rules=false listener=inactive");

    let (tx, rx) = oneshot::channel();
    let exit = handle_command(
        DaemonCommand::Shutdown { respond_to: tx },
        &mut state,
        &mut rules,
        &config,
        &output,
    )
    .await
    .unwrap();
    assert!(exit);
    let message = rx.await.unwrap().unwrap();
    assert_eq!(message, "shutting down");
}

#[tokio::test]
async fn handle_command_status_reports_finished_listener_as_inactive() {
    let shutdown = Arc::new(AtomicBool::new(false));
    let handle = tokio::spawn(async { Ok(()) });
    tokio::time::sleep(Duration::from_millis(10)).await;

    let mut state = DaemonState::new();
    state.listener = Some(ActiveListener { shutdown, handle });
    let mut rules = rule_engine();
    let config = empty_engine_config();
    let output = OutputController::new(None);

    let (tx, rx) = oneshot::channel();
    let exit = handle_command(
        DaemonCommand::Status { respond_to: tx },
        &mut state,
        &mut rules,
        &config,
        &output,
    )
    .await
    .unwrap();

    assert!(!exit);
    let message = rx.await.unwrap().unwrap();
    assert_eq!(message, "rules=0 receive_rules=false listener=inactive");
}

#[tokio::test]
async fn load_rules_with_startup_triggers_does_not_start_listener() {
    let mut state = DaemonState::new();
    let mut rules = rule_engine();
    let config = empty_engine_config();
    let output = OutputController::new(None);

    let yaml = r#"
- name: startup
  trigger: on_startup
  actions:
    - type: log
      message: "boot"
"#;
    let mut file = NamedTempFile::new().expect("create rule file");
    write!(file, "{}", yaml).expect("write rule file");
    file.flush().unwrap();

    let (tx, rx) = oneshot::channel();
    let exit = handle_command(
        DaemonCommand::LoadRules {
            path: file.path().to_string_lossy().to_string(),
            respond_to: tx,
        },
        &mut state,
        &mut rules,
        &config,
        &output,
    )
    .await
    .unwrap();

    assert!(!exit);
    let response = rx.await.unwrap().unwrap();
    assert_eq!(response, "loaded 1 rule(s)");
    assert!(rules.has_startup_triggers());
    assert!(!rules.has_receive_triggers());
    assert!(state.listener.is_none());
    assert!(state.listener_options.is_none());
}

#[tokio::test]
async fn stop_listener_without_active_listener_returns_success_response() {
    let mut state = DaemonState::new();
    let mut rules = rule_engine();
    let config = empty_engine_config();
    let output = OutputController::new(None);

    let (tx, rx) = oneshot::channel();
    let exit = handle_command(
        DaemonCommand::StopListener { respond_to: tx },
        &mut state,
        &mut rules,
        &config,
        &output,
    )
    .await
    .unwrap();

    assert!(!exit);
    let response = rx.await.unwrap().unwrap();
    assert_eq!(response, "listener stopped");
    assert!(state.listener.is_none());
}

#[test]
fn send_response_ignores_dropped_receivers() {
    let (tx, rx) = oneshot::channel();
    drop(rx);
    send_response(tx, Ok("ignored".to_string()));

    let (tx, rx) = oneshot::channel();
    drop(rx);
    send_response(tx, Err(anyhow!("failure")));
}

#[tokio::test]
async fn stop_listener_allows_graceful_task_shutdown() {
    use crate::network::interface::InterfaceError;
    use crate::network::listener::ListenerError;
    let shutdown = Arc::new(AtomicBool::new(true));
    let has_shutdown = Arc::new(AtomicBool::new(false));
    let has_shutdown_clone = Arc::clone(&has_shutdown);
    let shutdown_clone = Arc::clone(&shutdown);

    let handle = tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                Err(ListenerError::InterfaceLookup{ hint: Some("mock".to_string()), source: InterfaceError::NotFound{ name: "mock".to_string() }})
            }
            _ = async {
                while shutdown_clone.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            } => {
                has_shutdown_clone.store(true, Ordering::SeqCst);
                Ok(())
            }
        }
    });

    let mut state = DaemonState::new();
    state.listener = Some(ActiveListener { shutdown, handle });

    let result = stop_listener(&mut state).await;
    assert!(result.is_ok());
    assert!(
        has_shutdown.load(Ordering::SeqCst),
        "graceful shutdown should have completed"
    );
}

#[tokio::test]
async fn stop_listener_aborts_hanging_task_after_timeout() {
    let shutdown = Arc::new(AtomicBool::new(true));
    let handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    let mut state = DaemonState::new();
    state.listener = Some(ActiveListener { shutdown, handle });

    let result = stop_listener(&mut state).await;
    assert!(result.is_ok());
    assert!(state.listener.is_none());
}

#[cfg(feature = "pcap")]
#[tokio::test]
async fn start_listener_does_not_record_listener_when_capture_startup_fails() {
    let mut state = DaemonState::new();
    let rules = rule_engine();
    let config = empty_engine_config();
    let output = OutputController::new(None);
    let options = ListenerRequest {
        timeout: Some(5),
        ..Default::default()
    };

    let result = start_listener_with_interface_hint(
        &mut state,
        options,
        &config,
        &rules,
        &output,
        Some("__packetcraftr_missing_daemon_listener_interface__"),
    )
    .await;

    let err = result.expect_err("startup should fail before listener is recorded");
    assert!(
        err.to_string()
            .contains("__packetcraftr_missing_daemon_listener_interface__"),
        "error should include missing interface hint: {err}"
    );
    assert!(state.listener.is_none());
    assert!(state.listener_options.is_none());
}

#[cfg(not(feature = "pcap"))]
#[tokio::test]
async fn handle_command_listen_requires_pcap_feature() {
    let mut state = DaemonState::new();
    let mut rules = rule_engine();
    let config = empty_engine_config();
    let output = OutputController::new(None);

    let (tx, rx) = oneshot::channel();
    let exit = handle_command(
        DaemonCommand::Listen {
            options: ListenerRequest::default(),
            respond_to: tx,
        },
        &mut state,
        &mut rules,
        &config,
        &output,
    )
    .await
    .unwrap();

    assert!(!exit);
    let err = rx.await.unwrap().expect_err("listen should require pcap");
    assert!(
        err.to_string().contains("'pcap' feature"),
        "error should explain missing pcap feature: {err}"
    );
    assert!(state.listener.is_none());
    assert_eq!(rules.len(), 0);
    assert!(!rules.has_receive_triggers());
}

#[cfg(not(feature = "pcap"))]
#[tokio::test]
async fn load_receive_rules_requires_pcap_feature() {
    let mut state = DaemonState::new();
    let mut rules = rule_engine();
    let config = empty_engine_config();
    let output = OutputController::new(None);

    let yaml = r#"
- name: inbound
  trigger: on_receive
  actions:
    - type: log
      message: "packet"
"#;
    let mut file = NamedTempFile::new().expect("create rule file");
    write!(file, "{}", yaml).expect("write rule file");
    file.flush().unwrap();

    let (tx, rx) = oneshot::channel();
    let exit = handle_command(
        DaemonCommand::LoadRules {
            path: file.path().to_string_lossy().to_string(),
            respond_to: tx,
        },
        &mut state,
        &mut rules,
        &config,
        &output,
    )
    .await
    .unwrap();

    assert!(!exit);
    let err = rx
        .await
        .unwrap()
        .expect_err("receive rules should require pcap");
    assert!(
        err.to_string().contains("'pcap' feature"),
        "error should explain missing pcap feature: {err}"
    );
    assert!(state.listener.is_none());
    assert_eq!(rules.len(), 0);
    assert!(!rules.has_receive_triggers());
}
