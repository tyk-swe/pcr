use super::*;

#[test]
fn rule_engine_load_from_path_fails_if_file_missing() {
    let mut engine = RuleEngine::new().expect("rule engine initialisation");
    let result = engine.load_from_path("non-existent-file.yaml");
    assert!(result.is_err());
}

#[test]
fn rule_engine_load_from_path_fails_on_invalid_yaml() {
    let mut engine = RuleEngine::new().expect("rule engine initialisation");
    let mut file = tempfile::NamedTempFile::new().expect("create temp file");
    use std::io::Write;
    writeln!(file, "invalid: [yaml: structure").expect("write invalid yaml");

    let result = engine.load_from_path(file.path());
    assert!(result.is_err());
}

#[test]
fn rule_engine_load_from_path_fails_on_empty_rules() {
    let mut engine = RuleEngine::new().expect("rule engine initialisation");
    let mut file = tempfile::NamedTempFile::new().expect("create temp file");
    use std::io::Write;
    writeln!(file, "[]").expect("write empty rules list");

    let result = engine.load_from_path(file.path());
    assert!(matches!(result, Err(RuleError::EmptyRulesFile)));
}

#[test]
fn rule_engine_triggers_detection() {
    let mut engine = RuleEngine::new().expect("rule engine initialisation");
    let mut file = tempfile::NamedTempFile::new().expect("create temp file");
    use std::io::Write;
    let yaml = r#"
- name: "receive rule"
  trigger: on_receive
  actions:
    - type: log
      message: "receive"
- name: "timer rule"
  trigger: on_timer
  actions:
    - type: log
      message: "timer"
- name: "startup rule"
  trigger: on_startup
  actions:
    - type: log
      message: "startup"
"#;
    writeln!(file, "{}", yaml).expect("write rules");

    engine.load_from_path(file.path()).expect("load rules");

    assert_eq!(engine.len(), 3);
    assert!(engine.has_receive_triggers());
    assert!(engine.has_timer_triggers());
    assert!(engine.has_startup_triggers());
}

#[test]
fn rule_engine_load_from_path_allows_unknown_fields() {
    let mut engine = RuleEngine::new().expect("rule engine initialisation");
    let mut file = tempfile::NamedTempFile::new().expect("create temp file");
    use std::io::Write;
    let yaml = r#"
- name: "unknown-fields"
  trigger: on_receive
  extra_top_level: true
  condition:
    source:
      contains: "1.2.3.4"
      extra_matcher: "ignored"
  actions:
    - type: log
      message: "ok"
      extra_action: "ignored"
"#;
    writeln!(file, "{}", yaml).expect("write rules");

    engine.load_from_path(file.path()).expect("load rules");
    assert_eq!(engine.len(), 1);
}

#[test]
fn rule_engine_load_from_path_rejects_legacy_send_options_wrapper() {
    let mut engine = RuleEngine::new().expect("rule engine initialisation");
    let mut file = tempfile::NamedTempFile::new().expect("create temp file");
    use std::io::Write;
    let yaml = r#"
- name: "legacy-send-options"
  trigger: on_receive
  actions:
    - type: send
      options:
        destination:
          destination: "127.0.0.1"
"#;
    writeln!(file, "{}", yaml).expect("write rules");

    let result = engine.load_from_path(file.path());
    assert!(matches!(
        result,
        Err(RuleError::ActionContext {
            source: crate::rules::error::RuleActionError::LegacySendOptionsWrapper,
            ..
        })
    ));
}

#[test]
fn rule_engine_run_timer_actions_executes_only_timer_rules() {
    use crate::rules::executor::test_support;
    use std::sync::{mpsc, Arc, Mutex};
    let _executor_guard = test_support::executor_lock();
    let mut engine = RuleEngine::new().expect("rule engine initialisation");
    engine.configure_sender(RuleSendExecutor::new().expect("rule send executor initialisation"));

    let (tx, rx) = mpsc::channel();
    let tx = Arc::new(Mutex::new(tx));
    let _hook_guard = test_support::send_hook_guard(Some(Arc::new(move |rule_name, _| {
        tx.lock().unwrap().send(rule_name).unwrap();
        Ok(())
    })));

    let mut file = tempfile::NamedTempFile::new().expect("create temp file");
    use std::io::Write;
    let yaml = r#"
- name: "timer rule"
  trigger: on_timer
  actions:
    - type: send
- name: "receive rule"
  trigger: on_receive
  actions:
    - type: send
- name: "startup rule"
  trigger: on_startup
  actions:
    - type: send
"#;
    writeln!(file, "{}", yaml).expect("write rules");
    engine.load_from_path(file.path()).expect("load rules");

    engine.run_timer_actions();

    let received = rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("timer rule executed");
    assert_eq!(received, "timer rule");

    assert!(rx
        .recv_timeout(std::time::Duration::from_millis(100))
        .is_err());
}

#[test]
fn rule_engine_run_startup_actions_executes_only_startup_rules() {
    use crate::rules::executor::test_support;
    use std::sync::{mpsc, Arc, Mutex};
    let _executor_guard = test_support::executor_lock();
    let mut engine = RuleEngine::new().expect("rule engine initialisation");
    engine.configure_sender(RuleSendExecutor::new().expect("rule send executor initialisation"));

    let (tx, rx) = mpsc::channel();
    let tx = Arc::new(Mutex::new(tx));
    let _hook_guard = test_support::send_hook_guard(Some(Arc::new(move |rule_name, _| {
        tx.lock().unwrap().send(rule_name).unwrap();
        Ok(())
    })));

    let mut file = tempfile::NamedTempFile::new().expect("create temp file");
    use std::io::Write;
    let yaml = r#"
- name: "timer rule"
  trigger: on_timer
  actions:
    - type: send
- name: "receive rule"
  trigger: on_receive
  actions:
    - type: send
- name: "startup rule"
  trigger: on_startup
  actions:
    - type: send
"#;
    writeln!(file, "{}", yaml).expect("write rules");
    engine.load_from_path(file.path()).expect("load rules");

    engine.run_startup_actions();

    let received = rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("startup rule executed");
    assert_eq!(received, "startup rule");

    assert!(rx
        .recv_timeout(std::time::Duration::from_millis(100))
        .is_err());
}
