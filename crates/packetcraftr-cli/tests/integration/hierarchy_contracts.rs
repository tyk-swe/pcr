// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common::{parse_json, run, run_success};

const GROUPS: &[(&str, &[&str])] = &[
    ("packet", &["build", "dissect", "fragment", "fuzz"]),
    ("files", &["read", "merge", "rewrite", "export"]),
    (
        "analyze",
        &[
            "stats",
            "expert",
            "follow",
            "dns",
            "http",
            "http2",
            "tls",
            "verify-forwarding",
        ],
    ),
    (
        "network",
        &[
            "interfaces",
            "routes",
            "plan",
            "capture",
            "send",
            "exchange",
            "replay",
            "scan",
            "identify",
            "identify-os",
            "traceroute",
            "dns",
        ],
    ),
    ("reference", &["protocols", "topics", "documentation"]),
];

#[test]
fn all_paths_have_short_full_and_help_subcommand_help_without_work() {
    let root = run_success(&["--help"]);
    let root = String::from_utf8(root.stdout).unwrap();
    for (group, commands) in GROUPS {
        assert!(root.contains(group));
        let empty = run(&[group]);
        assert_eq!(empty.status.code(), Some(2));
        for command in *commands {
            let legacy = if *group == "analyze" && *command == "dns" {
                "dns-read"
            } else {
                command
            };
            for args in [
                vec![*group, command, "-h"],
                vec![*group, command, "--help"],
                vec!["help", group, command],
                vec![legacy, "--help"],
                vec!["help", legacy],
            ] {
                let output = run_success(&args);
                let text = String::from_utf8(output.stdout).unwrap();
                assert!(text.contains("Usage:"), "{args:?}: {text}");
                assert!(
                    text.contains(&format!("{group} {command}")),
                    "{args:?}: {text}"
                );
            }
        }
    }
    assert_eq!(run(&[]).status.code(), Some(2));
    let short = run_success(&["network", "scan", "-h"]);
    let full = run_success(&["network", "scan", "--help"]);
    assert!(short.stdout.len() < full.stdout.len());
    assert!(!String::from_utf8_lossy(&short.stdout).contains("--max-backoff-ms"));
    assert!(String::from_utf8_lossy(&full.stdout).contains("--max-backoff-ms"));
}

#[test]
fn invalid_arguments_keep_published_leaf_identifiers_at_every_path() {
    for (group, commands) in GROUPS {
        for command in *commands {
            if matches!(*command, "topics" | "documentation") {
                continue;
            }
            let legacy = if *group == "analyze" && *command == "dns" {
                "dns-read"
            } else {
                command
            };
            for args in [
                vec!["--output", "json", group, command, "--not-an-option"],
                vec![group, "--output", "json", command, "--not-an-option"],
                vec![group, command, "--output", "json", "--not-an-option"],
                vec![legacy, "--output", "json", "--not-an-option"],
            ] {
                let output = run(&args);
                assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
                let value = parse_json(&output);
                assert_eq!(value["command"], *legacy, "{args:?}");
                assert_eq!(value["error"]["kind"], "usage");
            }
        }
    }
}

#[test]
fn canonical_payloads_and_verbose_machine_output_are_identical() {
    for (group, command, legacy, rest) in [
        (
            "packet",
            "build",
            "build",
            vec!["--packet", "raw(text=hello)"],
        ),
        (
            "analyze",
            "stats",
            "stats",
            vec!["../../examples/captures/clock-regression.pcap"],
        ),
        (
            "analyze",
            "dns",
            "dns-read",
            vec!["../../examples/captures/tls-handshake.pcapng"],
        ),
        ("reference", "protocols", "protocols", vec![]),
    ] {
        let mut args = vec!["--output", "json", group, command];
        args.extend_from_slice(&rest);
        let canonical = run_success(&args);
        let mut args = vec!["--output", "json", "-v", legacy];
        args.extend_from_slice(&rest);
        let legacy = run_success(&args);
        assert_eq!(parse_json(&canonical), parse_json(&legacy));
    }
}

#[test]
fn nested_presets_preserve_explicit_overrides_and_resource_sources() {
    let output = run_success(&[
        "analyze",
        "--resource-preset",
        "ci-v1",
        "stats",
        "../../examples/captures/clock-regression.pcap",
        "--max-flows",
        "7",
        "--output",
        "json",
        "--resource-diagnostics",
    ]);
    let canonical = parse_json(&output);
    let legacy = parse_json(&run_success(&[
        "stats",
        "../../examples/captures/clock-regression.pcap",
        "--resource-preset",
        "ci-v1",
        "--max-flows",
        "7",
        "--output",
        "json",
        "--resource-diagnostics",
    ]));
    assert_eq!(canonical, legacy);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("preset:ci-v1"));
    assert!(text.contains("override"));
}

#[test]
fn separator_preserves_option_like_inputs_and_binary_payloads() {
    let output = run(&[
        "--output",
        "json",
        "files",
        "read",
        "--field",
        "frame.number",
        "--",
        "--not-an-option.pcap",
    ]);
    assert_ne!(output.status.code(), Some(2));
    assert_eq!(parse_json(&output)["command"], "read");
    let legacy = run_success(&["--output", "raw", "build", "--packet", "raw(hex=00011bff)"]);
    let canonical = run_success(&[
        "packet",
        "build",
        "--verbose",
        "--output",
        "raw",
        "--packet",
        "raw(hex=00011bff)",
    ]);
    assert_eq!(legacy.stdout, canonical.stdout);
    assert_eq!(canonical.stdout, [0, 1, 27, 255]);
}

#[test]
fn compact_and_verbose_text_keep_rows_warnings_and_terminal_escaping() {
    let base = [
        "files",
        "read",
        "../../examples/captures/clock-regression.pcap",
    ];
    let compact = run_success(&base);
    let verbose = run_success(&[base[0], base[1], base[2], "--verbose"]);
    assert!(compact.stdout.len() < verbose.stdout.len());
    for output in [&compact, &verbose] {
        assert!(
            !output.stdout.contains(&27),
            "redirected output must not contain ANSI"
        );
    }
    for color in ["always", "never"] {
        let output = run_success(&[
            "packet",
            "build",
            "--packet",
            "raw(text=hello)",
            "--color",
            color,
        ]);
        assert_eq!(output.stdout.contains(&27), color == "always");
    }
}

#[test]
fn omissions_and_explicit_detail_selectors_survive_compact_output() {
    for verbosity in [vec![], vec!["--verbose"]] {
        let mut args = vec![
            "analyze",
            "stats",
            "../../examples/captures/clock-regression.pcap",
            "--table",
            "protocols",
            "--top",
            "0",
        ];
        args.extend_from_slice(&verbosity);
        let output = run_success(&args);
        assert!(String::from_utf8_lossy(&output.stdout).contains("omitted"));
    }
    let bytes = "4500001c0000000040018eaac0000201c63364020800f7ff00000000";
    let output = run_success(&[
        "packet",
        "dissect",
        "--link-type",
        "228",
        "--hex",
        bytes,
        "--tree",
    ]);
    assert!(String::from_utf8_lossy(&output.stdout).contains("ttl ="));
    let output = run(&[
        "reference",
        "topics",
        "\u{1b}[31munknown",
        "--color",
        "never",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(!output.stderr.contains(&27));
}

#[test]
fn generated_documentation_covers_all_paths_and_five_shells() {
    let directory = tempfile::tempdir().unwrap();
    run_success(&[
        "reference",
        "documentation",
        "--directory",
        directory.path().to_str().unwrap(),
    ]);
    for (group, commands) in GROUPS {
        assert!(
            directory
                .path()
                .join(format!("man/packetcraftr-{group}.1"))
                .is_file()
        );
        for command in *commands {
            let legacy = if *group == "analyze" && *command == "dns" {
                "dns-read"
            } else {
                command
            };
            for path in [
                format!("man/packetcraftr-{group}-{command}.1"),
                format!("man/packetcraftr-{legacy}.1"),
            ] {
                assert!(directory.path().join(path).is_file());
            }
        }
    }
    for file in [
        "packetcraftr.bash",
        "packetcraftr.elv",
        "packetcraftr.fish",
        "_packetcraftr",
        "_packetcraftr.ps1",
    ] {
        let text =
            std::fs::read_to_string(directory.path().join("completions").join(file)).unwrap();
        for (group, _) in GROUPS {
            assert!(text.contains(group), "{file}: {group}");
        }
        assert!(text.contains("overview"), "{file}: overview");
        // These generators omit values for global options, including --output.
        if !matches!(file, "packetcraftr.elv" | "_packetcraftr.ps1") {
            assert!(text.contains("csv"), "{file}: csv");
        }
    }
    for file in ["packetcraftr-analyze-stats.1", "packetcraftr-stats.1"] {
        let text = std::fs::read_to_string(directory.path().join("man").join(file)).unwrap();
        for value in ["overview", "csv", "\\-\\-sort", "frames", "bytes"] {
            assert!(text.contains(value), "{file}: {value}");
        }
    }
    for file in ["packetcraftr-network-scan.1", "packetcraftr-scan.1"] {
        let text = std::fs::read_to_string(directory.path().join("man").join(file)).unwrap();
        for (option, description) in [
            (
                "udp\\-profiles",
                "Bounded per\\-port payload and response\\-check assignments (UDP profiles v1)",
            ),
            (
                "max\\-probes",
                "Maximum generated probes after target resolution and attempts",
            ),
            (
                "max\\-backoff\\-ms",
                "Ceiling on the retry delay in milliseconds (default 1000)",
            ),
        ] {
            let entry = text
                .split(".TP\n")
                .find(|entry| entry.starts_with(&format!("\\fB\\-\\-{option}\\fR")))
                .unwrap_or_else(|| panic!("{file}: missing option {option}"));
            assert!(entry.contains(description), "{file}: {entry}");
        }
    }
    assert_eq!(
        std::fs::read_dir(directory.path().join("man"))
            .unwrap()
            .count(),
        68
    );
    let mut entries = std::fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    entries.sort();
    assert_eq!(entries, ["completions", "man"]);
}
