use assert_cmd::Command;
use tempfile::tempdir;

fn command_result(args: &[&str]) -> std::process::Output {
    let temp_dir = tempdir().expect("temp dir for cli test");
    Command::cargo_bin("packetcraftr")
        .expect("binary should compile")
        .current_dir(temp_dir.path())
        .env("PACKETCRAFTR_HOME", temp_dir.path())
        .env("HOME", temp_dir.path())
        .args(args)
        .output()
        .expect("command should run")
}

fn command_output(args: &[&str]) -> String {
    let output = command_result(args);

    assert!(
        output.status.success(),
        "expected `packetcraftr {args:?}` to exit successfully, stderr: {stderr}",
        args = args,
        stderr = String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).expect("help output must be valid UTF-8")
}

#[test]
fn root_and_send_help_smoke() {
    let root = command_output(&["--help"]);
    for command in ["send", "dry-run", "dns-query"] {
        assert!(
            root.contains(&format!("\n  {command}")),
            "expected root help to include `{command}` command\n{root}"
        );
    }
    assert!(
        !root.contains("One-shot packet crafting:"),
        "expected root help to hide legacy one-shot flag surface\n{root}"
    );

    let send = command_output(&["send", "--help"]);
    for section in [
        "One-shot packet crafting:",
        "Layer 2 options:",
        "IP options:",
        "Transport options:",
        "Payload options:",
        "Transmission control:",
        "Automation:",
        "Logging:",
    ] {
        assert!(
            send.contains(section),
            "expected send help to include section heading `{section}`\n{send}"
        );
    }
}

#[test]
fn human_dry_run_summary_contains_destination_protocol_and_count() {
    let stdout = command_output(&[
        "dry-run",
        "--dest",
        "127.0.0.1",
        "udp",
        "--dport",
        "9",
        "--data",
        "hello",
    ]);

    assert!(stdout.contains("Summary:"), "missing summary\n{stdout}");
    assert!(
        stdout.contains("dest=127.0.0.1"),
        "missing destination\n{stdout}"
    );
    assert!(stdout.contains("proto=UDP"), "missing protocol\n{stdout}");
    assert!(stdout.contains("count=1"), "missing count\n{stdout}");
}

#[test]
fn json_dry_run_stdout_parses_without_log_prefixes() {
    let output = command_result(&[
        "--output-format",
        "json",
        "dry-run",
        "--dest",
        "127.0.0.1",
        "udp",
        "--dport",
        "9",
        "--data",
        "hello",
    ]);
    assert!(
        output.status.success(),
        "json dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    let json: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|err| panic!("{err}\nstdout:\n{stdout}"));

    assert_eq!(json["destination"], "127.0.0.1");
    assert_eq!(json["protocol"], "UDP");
    assert_eq!(json["count"], 1);
    assert_eq!(json["mode"], "L3");
    assert!(json["target"]["interface"].is_string());
    assert_eq!(json["transmit"]["auto_layer3"], true);
    assert_eq!(json["transmit"]["layer3_active"], true);
    assert!(
        !stdout.contains("[INFO"),
        "stdout contains log prefix\n{stdout}"
    );
}

#[test]
fn json_dry_run_planning_failure_has_empty_stdout() {
    let output = command_result(&["--output-format", "json", "dry-run", "udp", "--dport", "9"]);

    assert!(
        !output.status.success(),
        "expected missing destination dry-run to fail"
    );
    assert!(
        output.stdout.is_empty(),
        "planning failure should not emit success-like stdout\nstdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("destination address is required"),
        "stderr should explain destination failure\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn json_dry_run_rejects_unbounded_flood_before_hostname_resolution() {
    let output = command_result(&[
        "--output-format",
        "json",
        "dry-run",
        "--dest",
        "not a valid hostname",
        "--flood",
        "udp",
        "--dport",
        "9",
    ]);

    assert!(
        !output.status.success(),
        "expected unbounded flood dry-run to fail"
    );
    assert!(
        output.stdout.is_empty(),
        "policy failure should not emit success-like stdout\nstdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--flood without --count requires explicit unbounded-send opt-in"),
        "stderr should explain flood policy failure\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("resolve hostname failed"),
        "policy failure should happen before hostname resolution\nstderr:\n{stderr}"
    );
}

#[test]
fn json_dns_query_dry_run_stdout_parses() {
    let output = command_result(&[
        "--output-format",
        "json",
        "dns-query",
        "--dry-run",
        "--domain",
        "example.com",
    ]);

    assert!(
        output.status.success(),
        "json DNS dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("stdout should be valid JSON: {err}\nstdout:\n{stdout}"));
    assert_eq!(json["mode"], "dry_run");
    assert_eq!(json["query"]["domain"], "example.com");
    assert_eq!(json["query"]["record_type"], "A");
    assert_eq!(json["query"]["server"], "8.8.8.8");
    assert_eq!(json["query"]["timeout_ms"], 1000);
}

#[test]
fn verbose_logging_does_not_corrupt_json_stdout() {
    let output = command_result(&[
        "-v",
        "--output-format",
        "json",
        "dry-run",
        "--dest",
        "127.0.0.1",
        "udp",
        "--dport",
        "9",
        "--data",
        "hello",
    ]);
    assert!(
        output.status.success(),
        "verbose json dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    serde_json::from_str::<serde_json::Value>(&stdout)
        .unwrap_or_else(|err| panic!("{err}\nstdout:\n{stdout}"));
    assert!(!stdout.contains("INFO"), "stdout contains logs\n{stdout}");
    assert!(!stdout.contains("DEBUG"), "stdout contains logs\n{stdout}");
}
