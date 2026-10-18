// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common::{parse_json, path_text, run, run_success};

fn commands(help: &[u8]) -> Vec<String> {
    let text = std::str::from_utf8(help).unwrap();
    let (_, section) = text.split_once("Commands:\n").expect("command help");
    section
        .split("\n\n")
        .next()
        .unwrap()
        .lines()
        .filter_map(|line| line.strip_prefix("  "))
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| *name != "help")
        .map(str::to_owned)
        .collect()
}

#[test]
fn all_operations_have_grouped_help_and_manuals_and_reject_flat_paths() {
    let root = run_success(&["--help"]);
    let groups = commands(&root.stdout);
    assert_eq!(
        groups,
        ["packet", "files", "analyze", "network", "reference"]
    );
    let directory = tempfile::tempdir().unwrap();
    run_success(&[
        "reference",
        "documentation",
        "--directory",
        path_text(directory.path()),
    ]);
    let mut count = 0;
    for group in &groups {
        let empty = run(&[group]);
        assert_eq!(empty.status.code(), Some(2));
        let help = run_success(&[group, "--help"]);
        for command in commands(&help.stdout) {
            count += 1;
            let help = run_success(&[group, &command, "--help"]);
            assert_eq!(help.stdout, run_success(&["help", group, &command]).stdout);
            let text = String::from_utf8(help.stdout).unwrap();
            assert!(text.contains(&format!("Command: packetcraftr {group} {command}.")));
            assert!(!text.contains("Legacy alias:"));
            let short = run_success(&[group, &command, "-h"]);
            assert!(short.stdout.len() < text.len());
            let flat = if group == "analyze" && command == "dns" {
                "dns-read"
            } else {
                &command
            };
            for args in [vec![flat, "--help"], vec!["help", flat]] {
                assert_eq!(run(&args).status.code(), Some(2), "{args:?}");
            }
            let manual = directory
                .path()
                .join(format!("man/packetcraftr-{group}-{command}.1"));
            assert!(std::fs::metadata(manual).unwrap().len() > 0);
            assert!(
                !directory
                    .path()
                    .join(format!("man/packetcraftr-{flat}.1"))
                    .exists()
            );
        }
    }
    assert_eq!(count, 38);
    assert_eq!(
        std::fs::read_dir(directory.path().join("man"))
            .unwrap()
            .count(),
        44
    );
    let completions = std::fs::read_dir(directory.path().join("completions")).unwrap();
    let mut count = 0;
    for completion in completions {
        count += 1;
        let text = std::fs::read_to_string(completion.unwrap().path()).unwrap();
        for group in &groups {
            assert!(text.contains(group));
        }
    }
    assert_eq!(count, 5);
}

#[test]
fn globals_work_at_every_group_depth_and_errors_keep_compact_identifiers() {
    let globals = ["--output", "json", "--color", "never", "--verbose"];
    for depth in 0..=2 {
        let mut args = vec!["packet", "build"];
        args.splice(depth..depth, globals);
        args.extend(["--packet", "raw(text=hello)"]);
        let value = parse_json(&run_success(&args));
        assert_eq!(value["schema"], "packetcraftr.output/v1");
        assert_eq!(value["command"], "build");
        assert_eq!(value["result"]["bytes_hex"], "68656c6c6f");

        let mut valid = vec!["files", "read"];
        valid.splice(
            depth..depth,
            ["--output", "json", "--resource-preset", "ci-v1"],
        );
        valid.extend(["--field", "frame.number"]);
        valid.push(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/captures/tls-handshake.pcapng"
        ));
        assert_eq!(parse_json(&run_success(&valid))["command"], "read");

        let mut args = vec!["files", "read"];
        args.splice(
            depth..depth,
            ["--output", "json", "--resource-preset", "ci-v1"],
        );
        args.extend(["--max-frames", "0", "does-not-exist.pcap"]);
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(parse_json(&output)["command"], "read");
    }
    let error = run(&["--output", "json", "analyze", "dns", "--unknown-option"]);
    assert_eq!(error.status.code(), Some(2));
    assert_eq!(parse_json(&error)["command"], "dns-read");
    let removed = run(&["--output", "json", "dns-read"]);
    assert_eq!(removed.status.code(), Some(2));
    assert!(parse_json(&removed)["command"].is_null());
}
