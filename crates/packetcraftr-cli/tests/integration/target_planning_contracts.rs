// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write;

use serde_json::Value;

use crate::common::*;
use crate::process_support::run_with_stdin;

fn list_arguments<'a>(extra: &'a [&'a str]) -> Vec<&'a str> {
    let mut arguments = vec!["scan", "--list", "--output", "json"];
    arguments.extend(extra);
    arguments
}

fn manifest_file(contents: &[u8]) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("temp manifest");
    file.write_all(contents).expect("write manifest");
    file
}

fn result_targets(json: &Value) -> &[Value] {
    json["result"]["targets"].as_array().expect("targets")
}

fn addresses(json: &Value) -> Vec<&str> {
    result_targets(json)
        .iter()
        .map(|target| target["address"].as_str().expect("address"))
        .collect()
}

#[test]
fn list_json_reports_targets_origins_and_no_resolution() {
    let output = run_success(&list_arguments(&["192.0.2.1", "10.0.0.0/30", "192.0.2.1"]));
    let json = parse_json(&output);
    assert_eq!(json["result"]["method"], "target_list");
    assert_eq!(json["result"]["resolution_performed"], false);
    assert_eq!(
        addresses(&json),
        ["192.0.2.1", "10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"]
    );
    let origins = &result_targets(&json)[0]["origins"];
    assert_eq!(origins.as_array().expect("origins").len(), 2);
    assert_eq!(origins[0]["index"], 0);
    assert_eq!(origins[0]["source"], "argument 1");
    assert_eq!(origins[1]["index"], 2);
    assert_eq!(origins[1]["source"], "argument 3");
    assert_eq!(
        json["result"]["duplicates"],
        serde_json::json!([{"index": 2, "source": "argument 3"}])
    );
}

#[test]
fn list_ndjson_streams_targets_then_one_terminal() {
    let output = run_success(&[
        "scan",
        "--list",
        "--output",
        "ndjson",
        "192.0.2.1",
        "10.0.0.0/30",
    ]);
    let records = parse_ndjson(&output);
    assert_contiguous(&records);
    let (events, terminal) = records.split_at(records.len() - 1);
    assert_eq!(events.len(), 5);
    for record in events {
        assert_eq!(record["event"], "target");
        assert_eq!(record["result"]["method"], "target_list");
    }
    assert_eq!(terminal[0]["event"], "complete");
    assert_eq!(terminal[0]["result"]["count"], 5);
}

#[test]
fn list_text_lists_each_target_with_its_origins() {
    let output = run_success(&["scan", "--list", "--output", "text", "192.0.2.1"]);
    let text = String::from_utf8(output.stdout).expect("text output");
    assert!(text.contains("192.0.2.1"), "{text}");
    assert!(text.contains("argument 1"), "{text}");
    assert!(text.contains("resolution_performed=false"), "{text}");
}

#[test]
fn argument_file_and_stdin_inputs_select_identically() {
    let positional_out = run_success(&list_arguments(&["192.0.2.9", "10.0.0.0/30", "192.0.2.1"]));
    let file = manifest_file(b"10.0.0.0/30\n192.0.2.1\n");
    let file_path = path_text(file.path());
    let file_out = run_success(&list_arguments(&["192.0.2.9", "--targets-file", file_path]));
    let stdin_out = run_with_stdin(
        &list_arguments(&["192.0.2.9", "--targets-file", "-"]),
        b"10.0.0.0/30\n192.0.2.1\n",
    );
    assert!(stdin_out.status.success(), "{stdin_out:?}");
    let positional_json = parse_json(&positional_out);
    let file_json = parse_json(&file_out);
    let stdin_json = parse_json(&stdin_out);
    let expected = [
        "192.0.2.9",
        "10.0.0.0",
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
        "192.0.2.1",
    ];
    assert_eq!(addresses(&positional_json), expected);
    assert_eq!(addresses(&file_json), expected);
    assert_eq!(addresses(&stdin_json), expected);
    assert_eq!(result_targets(&stdin_json)[1]["origins"][0]["index"], 1);
    assert_eq!(
        result_targets(&stdin_json)[1]["origins"][0]["line"],
        1,
        "the stdin origin keeps its physical line"
    );
    assert_eq!(result_targets(&stdin_json)[5]["origins"][0]["line"], 2);
    let origins: Vec<String> = result_targets(&stdin_json)
        .iter()
        .flat_map(|target| {
            target["origins"]
                .as_array()
                .expect("origins")
                .iter()
                .map(|origin| origin["source"].as_str().expect("source").to_owned())
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(
        origins.iter().any(|source| source == "stdin"),
        "{origins:?}"
    );
    assert_eq!(
        result_targets(&file_json)[1]["origins"][0]["source"],
        file_path
    );
    assert_eq!(
        result_targets(&file_json)[5]["origins"][0]["index"],
        2,
        "the second manifest line keeps its physical position"
    );
}

#[test]
fn exclusions_and_family_narrow_the_list() {
    let output = run_success(&list_arguments(&[
        "10.0.0.0/30",
        "--exclude",
        "10.0.0.1",
        "--exclude",
        "10.0.0.2",
    ]));
    let json = parse_json(&output);
    assert_eq!(addresses(&json), ["10.0.0.0", "10.0.0.3"]);

    let output = run_success(&list_arguments(&[
        "10.0.0.1",
        "2001:db8::1",
        "--family",
        "ipv4",
    ]));
    let json = parse_json(&output);
    assert_eq!(addresses(&json), ["10.0.0.1"]);
}

#[test]
fn exclude_files_share_the_include_manifest_budget() {
    let targets = manifest_file(b"192.0.2.1\n");
    let excludes = manifest_file(b"192.0.2.2\n");
    let output = run_success(&list_arguments(&[
        "--targets-file",
        path_text(targets.path()),
        "--exclude-file",
        path_text(excludes.path()),
    ]));
    assert_eq!(addresses(&parse_json(&output)), ["192.0.2.1"]);
    let mut args = vec!["scan", "--list", "--max-manifest-bytes", "10"];
    args.extend([
        "--targets-file",
        path_text(targets.path()),
        "--exclude-file",
        path_text(excludes.path()),
    ]);
    let output = run(&args);
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("byte limit"), "{stderr}");
}

#[test]
fn repeated_stdin_is_rejected_across_and_within_flags() {
    for args in [
        &[
            "scan",
            "--list",
            "--targets-file",
            "-",
            "--targets-file",
            "-",
            "192.0.2.1",
        ][..],
        &[
            "scan",
            "--list",
            "--targets-file",
            "-",
            "--exclude-file",
            "-",
            "192.0.2.1",
        ][..],
    ] {
        let output = run_with_stdin(args, b"192.0.2.1\n");
        assert!(!output.status.success(), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("stdin"), "{stderr}");
    }
}

#[test]
fn an_empty_stdin_manifest_behaves_like_an_empty_file() {
    let output = run_with_stdin(&list_arguments(&["192.0.2.1", "--targets-file", "-"]), b"");
    assert!(output.status.success(), "{output:?}");
    let json = serde_json::from_slice::<Value>(&output.stdout).expect("JSON");
    assert_eq!(addresses(&json), ["192.0.2.1"]);
}

fn output_text(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    )
}

#[test]
fn malformed_and_oversized_manifests_fail_before_work() {
    let bad_utf8 = manifest_file(b"\xff\xfe");
    let output = run(&list_arguments(&[
        "--targets-file",
        path_text(bad_utf8.path()),
    ]));
    assert!(!output.status.success());
    assert!(output_text(&output).contains("UTF-8"));

    let two_tokens = manifest_file(b"one two\n");
    let output = run(&list_arguments(&[
        "--targets-file",
        path_text(two_tokens.path()),
    ]));
    assert!(!output.status.success());
    assert!(output_text(&output).contains("extra tokens"));

    let many = manifest_file(b"10.0.0.1\n10.0.0.2\n10.0.0.3\n");
    let output = run(&list_arguments(&[
        "--targets-file",
        path_text(many.path()),
        "--max-targets",
        "2",
    ]));
    assert!(!output.status.success());
    assert!(output_text(&output).contains("max_targets"));
}

#[test]
fn invalid_target_declarations_keep_classification_and_provenance() {
    for (token, code, remediation) in [
        (
            "bad..example",
            "cli.live_target",
            "use a valid IP address or bounded ASCII DNS hostname",
        ),
        (
            "192.0.2.1/33",
            "cli.target_selection",
            "supply explicit bounded host/IP/CIDR targets and numeric exclusions",
        ),
    ] {
        let contents = format!("# declarations\n\n{token}\n");
        let file = manifest_file(contents.as_bytes());
        let path = path_text(file.path());
        for (output, label) in [
            (run(&list_arguments(&[token])), "argument 1".to_owned()),
            (
                run(&list_arguments(&["--targets-file", path])),
                format!("{path}:3"),
            ),
            (
                run_with_stdin(
                    &list_arguments(&["--targets-file", "-"]),
                    contents.as_bytes(),
                ),
                "stdin:3".to_owned(),
            ),
        ] {
            assert_eq!(output.status.code(), Some(2), "{output:?}");
            let json = parse_json(&output);
            let error = &json["error"];
            assert_eq!(error["code"], code, "{json}");
            assert_eq!(error["kind"], "usage");
            assert_eq!(error["remediation"], remediation);
            assert!(
                error["message"].as_str().unwrap().contains(&label),
                "{json}"
            );
            assert!(
                error["causes"][0].as_str().unwrap().contains(token),
                "{json}"
            );
        }
    }
}

#[test]
fn invalid_exclusion_manifest_keeps_classification_and_provenance() {
    let file = manifest_file(b"# exclusions\n192.0.2.1/33\n");
    let path = path_text(file.path());
    let output = run(&list_arguments(&["192.0.2.1", "--exclude-file", path]));
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let json = parse_json(&output);
    let error = &json["error"];
    assert_eq!(error["code"], "cli.target_selection");
    assert_eq!(
        error["remediation"],
        "supply explicit bounded host/IP/CIDR targets and numeric exclusions"
    );
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains(&format!("{path}:2")),
        "{json}"
    );
    assert!(
        error["causes"][0]
            .as_str()
            .unwrap()
            .contains("192.0.2.1/33"),
        "{json}"
    );
}

#[test]
fn a_family_empty_plan_and_a_missing_scope_fail() {
    let output = run(&list_arguments(&["2001:db8::1", "--family", "ipv4"]));
    assert!(!output.status.success(), "{output:?}");

    let output = run(&list_arguments(&["fe80::1"]));
    assert!(!output.status.success(), "{output:?}");
    let text = output_text(&output);
    assert!(text.contains("scope") || text.contains("zone"), "{text}");
}

#[test]
fn hostname_resolution_requires_the_opt_in_and_reports_it() {
    let output = run(&list_arguments(&["localhost"]));
    assert!(!output.status.success(), "{output:?}");
    let text = output_text(&output);
    assert!(
        text.contains("hostname") || text.contains("resolution"),
        "{text}"
    );

    let output = run_success(&list_arguments(&[
        "localhost",
        "--allow-hostname-resolution",
    ]));
    let json = parse_json(&output);
    assert_eq!(json["result"]["resolution_performed"], true);
    assert!(
        result_targets(&json)
            .iter()
            .any(|target| target["address"].as_str() == Some("127.0.0.1")),
        "{json}"
    );
}

#[test]
fn no_target_declarations_fails() {
    let output = run(&list_arguments(&[]));
    assert!(!output.status.success(), "{output:?}");
}

#[test]
fn connect_via_file_and_stdin_targets_uses_real_loopback() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
    let port = listener
        .local_addr()
        .expect("local addr")
        .port()
        .to_string();
    let manifest = manifest_file(b"127.0.0.1\n");
    for (args, stdin) in [
        (vec!["--targets-file", path_text(manifest.path())], None),
        (vec!["--targets-file", "-"], Some(b"127.0.0.1\n".as_slice())),
    ] {
        let mut arguments = vec![
            "scan",
            "--connect",
            "--attempts",
            "1",
            "--max-probes",
            "1",
            "--ports",
            &port,
            "--output",
            "json",
        ];
        arguments.extend(args.iter().copied());
        let output = match stdin {
            Some(input) => run_with_stdin(&arguments, input),
            None => run(&arguments),
        };
        assert!(output.status.success(), "{output:?}");
        let json = parse_json(&output);
        let probe = json["result"]["endpoints"][0]["probes"][0].clone();
        assert_eq!(probe["outcome"], "connected", "{json}");
    }
}
