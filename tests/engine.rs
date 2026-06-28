// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::cli::{
    IpOptions, Layer2Options, ListenOptions, LoggingOptions, OneShotOptions, PayloadOptions,
    RuleOptions, TransmitOptions, TransportOptions,
};
use packetcraftr::engine::request::PacketRequest;
use packetcraftr::engine::{Engine, EngineConfig};
use std::io::Write;
use tempfile::NamedTempFile;

fn default_config() -> EngineConfig {
    EngineConfig {
        output_format: None,
        prometheus_bind: None,
        rule_workers: None,
        rule_queue: None,
        send_workers: None,
        send_queue: None,
        allow_unbounded_sends: false,
        dry_run: false,
    }
}

fn write_rules(docs: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("failed to create temporary rule file");
    writeln!(file, "{}", docs.trim()).expect("failed to write rules");
    file
}

fn options_with_rules_file(rules_file: String) -> OneShotOptions {
    OneShotOptions {
        destination: Some("127.0.0.1".to_string()),
        layer2: Layer2Options::default(),
        ip: IpOptions::default(),
        transport: TransportOptions::default(),
        payload: PayloadOptions::default(),
        transmit: TransmitOptions::default(),
        listen: ListenOptions::default(),
        logging: LoggingOptions::default(),
        rule: RuleOptions {
            rules_file: Some(rules_file),
            ..Default::default()
        },
    }
}

#[tokio::test]
async fn test_run_one_shot_dry_run_skips_privilege_checks() {
    let mut config = default_config();
    config.dry_run = true;
    let mut engine = Engine::new(config).expect("engine initialisation");
    let options = OneShotOptions {
        destination: Some("127.0.0.1".to_string()),
        layer2: Layer2Options::default(),
        ip: IpOptions::default(),
        transport: TransportOptions::default(),
        payload: PayloadOptions::default(),
        transmit: TransmitOptions {
            interface: Some("lo".to_string()),
            ..Default::default()
        },
        listen: ListenOptions::default(),
        logging: LoggingOptions::default(),
        rule: RuleOptions {
            rules_file: None,
            ..Default::default()
        },
    };
    let result = engine.run_one_shot(PacketRequest::from(&options)).await;
    assert!(
        result.is_ok(),
        "dry-run should succeed without raw socket privileges: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn unbounded_flood_policy_rejects_before_rules_load() {
    let rules = r#"
- name: "startup"
  trigger: on_startup
  actions:
    - type: log
      message: "startup"
"#;
    let rules_file = write_rules(rules);
    let rules_path = rules_file
        .path()
        .to_str()
        .expect("rules path should be valid UTF-8")
        .to_string();
    let mut engine = Engine::new(default_config()).expect("engine initialisation");
    let mut options = options_with_rules_file(rules_path);
    options.transmit.flood = Some(true);

    let result = engine.run_one_shot(PacketRequest::from(&options)).await;

    assert!(
        result.is_err(),
        "unbounded flood should be rejected before one-shot execution"
    );
    let error = result.expect_err("unbounded flood should fail").to_string();
    assert!(
        error.contains("--flood without --count requires explicit unbounded-send opt-in"),
        "unexpected error: {error}"
    );
    assert_eq!(
        engine.rule_count(),
        0,
        "policy rejection should happen before rules are loaded"
    );
}

#[tokio::test]
async fn zero_count_policy_rejects_before_hostname_resolution() {
    let mut engine = Engine::new(default_config()).expect("engine initialisation");
    let mut options = options_with_rules_file("unused-rules.yml".to_string());
    options.destination = Some("invalid/host".to_string());
    options.transmit.count = Some(0);

    let result = engine.run_one_shot(PacketRequest::from(&options)).await;

    assert!(result.is_err(), "zero count should be rejected");
    let error = result.expect_err("zero count should fail").to_string();
    assert!(
        error.contains("--count must be greater than zero"),
        "unexpected error: {error}"
    );
    assert!(
        !error.contains("resolve hostname failed"),
        "count validation should happen before hostname resolution: {error}"
    );
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn invalid_rules_file_fails_before_live_transmission_planning() {
    let rules_file = write_rules("not: a rule list");
    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let metrics_path = temp_dir.path().join("metrics.json");
    let rules_path = rules_file
        .path()
        .to_str()
        .expect("rules path should be valid UTF-8")
        .to_string();

    let mut engine = Engine::new(default_config()).expect("engine initialisation");
    let mut options = options_with_rules_file(rules_path);
    options.transmit.interface = Some("lo".to_string());
    options.transmit.force_layer3 = Some(true);
    options.logging.metrics_json = Some(metrics_path.to_string_lossy().into_owned());

    let result = engine.run_one_shot(PacketRequest::from(&options)).await;

    assert!(result.is_err(), "invalid rules file should fail");
    assert!(
        !metrics_path.exists(),
        "live planning should not write metrics before rules are validated"
    );
}
