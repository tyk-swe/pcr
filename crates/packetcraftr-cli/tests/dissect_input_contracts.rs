// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Hexadecimal text input, shared link-type names, and the field tree view of `dissect` and
// `read --dissect`.

use std::io::Write;

#[path = "common/capture.rs"]
mod capture_support;
mod common;
#[path = "common/process.rs"]
mod process_support;

use capture_support::write_pcap_hex;
use common::{path_text, run, run_success};
use process_support::run_with_stdin;

/// 192.0.2.1:40000 to 192.0.2.2:53 carrying a DNS question for example.test.
const DNS_QUERY: &str = "4500003a000000004011f6afc0000201c00002029c4000350026a7a1\
                         000000000001000000000000076578616d706c6504746573740000010001";

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("text output is UTF-8")
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn hex_file(contents: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    file.flush().unwrap();
    file
}

#[test]
fn built_hex_pipes_into_dissect_over_stdin() {
    let built = run_success(&[
        "--output",
        "hex",
        "build",
        "--packet",
        "ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=40000,dport=9)/raw(text=hi)",
    ]);
    let piped = run_with_stdin(
        &["dissect", "--link-type", "ipv4", "--hex", "-"],
        &built.stdout,
    );
    assert!(piped.status.success(), "{}", stderr(&piped));
    let text = stdout(&piped);
    assert!(text.contains("into 3 layer(s)"), "{text}");
    assert!(!text.contains("malformed"), "{text}");
    let inline = run_success(&[
        "dissect",
        "--link-type",
        "ipv4",
        "--hex",
        String::from_utf8_lossy(&built.stdout).trim(),
    ]);
    assert_eq!(piped.stdout, inline.stdout);
}

#[test]
fn hex_files_tolerate_separators_prefixes_and_newlines() {
    let separated = DNS_QUERY
        .as_bytes()
        .chunks(2)
        .map(|pair| std::str::from_utf8(pair).unwrap())
        .collect::<Vec<_>>()
        .chunks(8)
        .map(|line| line.join(":"))
        .collect::<Vec<_>>()
        .join("\n");
    let inline = run_success(&["dissect", "--link-type", "ipv4", "--hex", DNS_QUERY]);
    for text in [
        format!("{separated}\n"),
        format!("\n  0x{DNS_QUERY}\r\n"),
        DNS_QUERY.to_ascii_uppercase(),
    ] {
        let file = hex_file(&text);
        let output = run_success(&[
            "dissect",
            "--link-type",
            "ipv4",
            "--hex-file",
            path_text(file.path()),
        ]);
        assert_eq!(output.stdout, inline.stdout, "{text:?}");
        let piped = run_with_stdin(
            &["dissect", "--link-type", "ipv4", "--hex", "-"],
            text.as_bytes(),
        );
        assert_eq!(piped.stdout, inline.stdout, "{text:?}");
    }
}

#[test]
fn hex_text_and_decoded_bytes_are_bounded_by_the_packet_budget() {
    // Four text bytes per packet byte plus 4096 of slack is the most hex text read.
    let oversized = hex_file(&"00".repeat(4096 + 4 * 8));
    let output = run(&[
        "dissect",
        "--link-type",
        "ipv4",
        "--max-packet-size",
        "8",
        "--hex-file",
        path_text(oversized.path()),
    ]);
    assert_eq!(output.status.code(), Some(6), "{}", stderr(&output));
    assert!(stderr(&output).contains("frame hex text input exceeds"));
    assert!(output.stdout.is_empty());

    let piped = run_with_stdin(
        &[
            "dissect",
            "--link-type",
            "ipv4",
            "--max-packet-size",
            "8",
            "--hex",
            "-",
        ],
        "00".repeat(4096 + 4 * 8).as_bytes(),
    );
    assert_eq!(piped.status.code(), Some(6));

    // The text fits its bound, but the decoded frame does not fit the packet budget.
    let output = run_with_stdin(
        &[
            "dissect",
            "--link-type",
            "ipv4",
            "--max-packet-size",
            "8",
            "--hex",
            "-",
        ],
        DNS_QUERY.as_bytes(),
    );
    assert_eq!(output.status.code(), Some(6), "{}", stderr(&output));
    assert!(stderr(&output).contains("policy.decode_resource_limit"));
    assert!(output.stdout.is_empty());
}

#[test]
fn malformed_hex_text_keeps_the_inline_usage_errors() {
    for (text, message) in [
        ("abc", "even number of digits"),
        ("zz00", "invalid hex at byte 0"),
        ("00 0g", "invalid hex at byte 1"),
    ] {
        let inline = run(&["dissect", "--link-type", "ipv4", "--hex", text]);
        let file = hex_file(text);
        let from_file = run(&[
            "dissect",
            "--link-type",
            "ipv4",
            "--hex-file",
            path_text(file.path()),
        ]);
        let piped = run_with_stdin(
            &["dissect", "--link-type", "ipv4", "--hex", "-"],
            text.as_bytes(),
        );
        for output in [&inline, &from_file, &piped] {
            assert_eq!(output.status.code(), Some(2), "{text}");
            assert!(stderr(output).contains(message), "{}", stderr(output));
            assert!(output.stdout.is_empty());
        }
    }
    let invalid_utf8 = run_with_stdin(
        &["dissect", "--link-type", "ipv4", "--hex", "-"],
        &[0xff, 0xfe],
    );
    assert_eq!(invalid_utf8.status.code(), Some(2));
    let empty = run_with_stdin(&["dissect", "--link-type", "ipv4", "--hex", "-"], b"");
    assert_eq!(empty.status.code(), Some(2));
    assert!(stderr(&empty).contains("frame hex text input is required"));
    // Text that decodes to no bytes is as missing as no text.
    for blank in ["\n  \n", "0x", " 0x\n"] {
        let piped = run_with_stdin(
            &["dissect", "--link-type", "ipv4", "--hex", "-"],
            blank.as_bytes(),
        );
        let file = hex_file(blank);
        let from_file = run(&[
            "dissect",
            "--link-type",
            "ipv4",
            "--hex-file",
            path_text(file.path()),
        ]);
        for output in [&piped, &from_file] {
            assert_eq!(output.status.code(), Some(2), "{blank:?}");
            assert!(stderr(output).contains("cli.input_source"), "{blank:?}");
            assert!(stderr(output).contains("frame hex text input is required"));
            assert!(output.stdout.is_empty());
        }
    }
}

#[test]
fn hex_sources_conflict_and_bare_stdin_stays_raw_bytes() {
    let file = hex_file(DNS_QUERY);
    let raw = tempfile::NamedTempFile::new().unwrap();
    for arguments in [
        vec![
            "--hex-file",
            path_text(file.path()),
            "--file",
            path_text(raw.path()),
        ],
        vec!["--hex-file", path_text(file.path()), "--hex", DNS_QUERY],
        vec!["--hex", DNS_QUERY, "--file", path_text(raw.path())],
    ] {
        let mut command = vec!["dissect", "--link-type", "ipv4"];
        command.extend(arguments);
        let output = run(&command);
        assert_eq!(output.status.code(), Some(2), "{command:?}");
        assert!(output.stdout.is_empty());
    }

    let bytes = process_support::decode_hex(DNS_QUERY);
    let from_stdin = run_with_stdin(&["dissect", "--link-type", "ipv4"], &bytes);
    let inline = run_success(&["dissect", "--link-type", "ipv4", "--hex", DNS_QUERY]);
    assert_eq!(from_stdin.stdout, inline.stdout);
}

#[test]
fn link_type_names_match_their_numbers_in_dissect() {
    let ethernet_frame = format!("020000000002020000000001 0800 {DNS_QUERY}").replace(' ', "");
    for (name, number, frame) in [
        ("ipv4", "228", DNS_QUERY),
        ("ethernet", "1", ethernet_frame.as_str()),
        ("raw", "101", DNS_QUERY),
    ] {
        let named = run_success(&["dissect", "--link-type", name, "--hex", frame]);
        let numbered = run_success(&["dissect", "--link-type", number, "--hex", frame]);
        assert_eq!(named.stdout, numbered.stdout, "{name}");
    }
    let default = run_success(&["dissect", "--hex", &ethernet_frame]);
    let explicit = run_success(&[
        "dissect",
        "--link-type",
        "ethernet",
        "--hex",
        &ethernet_frame,
    ]);
    assert_eq!(default.stdout, explicit.stdout);
    assert!(stdout(&default).contains("0: ethernet"));
    let sll = run_success(&["dissect", "--link-type", "113", "--hex", "0000000000000000"]);
    assert!(sll.status.success());
}

#[test]
fn unnamed_link_types_parse_and_each_command_applies_its_own_root_rules() {
    // The shared parser accepts any decimal; dissect decodes an unrooted type as raw bytes.
    let dissected = run_success(&["dissect", "--link-type", "147", "--hex", "450000"]);
    let text = stdout(&dissected);
    assert!(text.contains("0: raw"), "{text}");

    // Build still refuses link types with no built-in decode root, after parsing 147.
    let built = run(&[
        "--output",
        "pcap",
        "build",
        "--packet",
        "ipv4()",
        "--link-type",
        "147",
    ]);
    assert_eq!(built.status.code(), Some(2));
    let message = stderr(&built);
    assert!(
        message.contains("link type 147 has no built-in decode root"),
        "{message}"
    );
    assert!(!message.contains("unknown link type"), "{message}");
}

#[test]
fn unknown_link_type_names_list_the_accepted_names_in_both_commands() {
    for arguments in [
        vec!["dissect", "--link-type", "bogus", "--hex", "00"],
        vec![
            "--output",
            "pcap",
            "build",
            "--packet",
            "ipv4()",
            "--link-type",
            "bogus",
        ],
    ] {
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        let message = stderr(&output);
        assert!(message.contains("unknown link type \"bogus\""), "{message}");
        assert!(
            message.contains("ethernet") && message.contains("linux-sll2"),
            "{message}"
        );
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn dissect_tree_prints_layers_with_nested_and_derived_fields() {
    let output = run_success(&[
        "dissect",
        "--link-type",
        "ipv4",
        "--tree",
        "--hex",
        DNS_QUERY,
    ]);
    let text = stdout(&output);
    let lines = text.lines().collect::<Vec<_>>();
    assert_eq!(lines[0], "decoded 58 bytes into 3 layer(s)");
    for header in ["0: ipv4", "1: udp", "2: dns"] {
        assert!(lines.contains(&header), "{header}\n{text}");
    }
    for field in [
        "  ttl = 64",
        "  checksum = 63151 (derived)",
        "  source = 192.0.2.1",
        "  options = (0 bytes)",
        "  questions:",
        "    [0]:",
        "      name = \"example.test.\"",
        "      type = 1",
        "  wire = 000000000001000000000000076578616d706c6504746573740000010001 (30 bytes)",
    ] {
        assert!(lines.contains(&field), "{field}\n{text}");
    }
    // Layers keep their order and their fields follow their headers.
    let position = |line: &str| {
        lines
            .iter()
            .position(|candidate| *candidate == line)
            .unwrap()
    };
    assert!(position("0: ipv4") < position("  ttl = 64"));
    assert!(position("  ttl = 64") < position("1: udp"));
    assert!(position("1: udp") < position("2: dns"));
    // The tree replaces the DNS summary lines rather than repeating them.
    assert!(!text.contains("dns question:"));

    let plain = run_success(&["dissect", "--link-type", "ipv4", "--hex", DNS_QUERY]);
    assert_eq!(
        stdout(&plain),
        "decoded 58 bytes into 3 layer(s)\n0: ipv4\n1: udp\n2: dns\n  dns question: example.test. type=1 class=1\n"
    );
}

#[test]
fn dissect_tree_shows_malformed_layer_bytes_and_escapes_control_text() {
    let malformed = run_success(&[
        "dissect",
        "--link-type",
        "ipv4",
        "--tree",
        "--hex",
        "450000",
    ]);
    let text = stdout(&malformed);
    assert!(text.contains("0: malformed\n"), "{text}");
    assert!(text.contains("  bytes = 450000 (3 bytes)\n"), "{text}");

    // The decoded name carries an ESC label byte; no raw control byte reaches stdout.
    let escape = DNS_QUERY.replace("076578616d706c65", "071b78616d706c65");
    let output = run_success(&["dissect", "--link-type", "ipv4", "--tree", "--hex", &escape]);
    assert!(!output.stdout.contains(&0x1b));
    assert!(stdout(&output).contains("xample.test."));
}

#[test]
fn dissect_tree_is_text_only_and_budgeted() {
    for format in ["json", "ndjson", "hex", "raw", "csv", "tsv"] {
        let output = run(&[
            "--output",
            format,
            "dissect",
            "--link-type",
            "ipv4",
            "--hex",
            DNS_QUERY,
            "--tree",
        ]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{format}: {}",
            stderr(&output)
        );
        // Machine formats report the error on stdout, byte formats on stderr.
        let reported = format!("{}{}", stdout(&output), stderr(&output));
        assert!(
            reported.contains(&format!("--tree has no effect on {format} output")),
            "{format}: {reported}"
        );
        if matches!(format, "hex" | "raw") {
            assert!(output.stdout.is_empty(), "{format}");
        }
    }

    // Exactly enough budget passes; one byte less fails with the typed policy error.
    let full = run_success(&[
        "dissect",
        "--link-type",
        "ipv4",
        "--tree",
        "--hex",
        DNS_QUERY,
    ]);
    let tree_bytes = stdout(&full)
        .lines()
        .skip(1)
        .map(|line| line.len() + 1)
        .sum::<usize>();
    let exact = tree_bytes.to_string();
    let enough = run_success(&[
        "dissect",
        "--link-type",
        "ipv4",
        "--tree",
        "--max-tree-bytes",
        &exact,
        "--hex",
        DNS_QUERY,
    ]);
    assert_eq!(enough.stdout, full.stdout);
    let short = (tree_bytes - 1).to_string();
    let limited = run(&[
        "dissect",
        "--link-type",
        "ipv4",
        "--tree",
        "--max-tree-bytes",
        &short,
        "--hex",
        DNS_QUERY,
    ]);
    assert_eq!(limited.status.code(), Some(6));
    assert!(
        stderr(&limited).contains("policy.tree_output_limit"),
        "{}",
        stderr(&limited)
    );
    assert!(stderr(&limited).contains("--max-tree-bytes"));
    assert!(stdout(&limited).len() < stdout(&full).len());

    let with_field = run(&[
        "dissect",
        "--link-type",
        "ipv4",
        "--tree",
        "--field",
        "ip.src",
        "--hex",
        DNS_QUERY,
    ]);
    assert_eq!(with_field.status.code(), Some(2));
}

#[test]
fn read_dissect_tree_prefixes_each_frame_and_leaves_plain_output_unchanged() {
    let capture = write_pcap_hex(&[DNS_QUERY, DNS_QUERY]);
    let path = path_text(capture.path());
    let plain = run_success(&["read", path, "--dissect"]);
    let line = format!(
        "dlt=228 caplen=58 wirelen=58 layers=ipv4/udp/dns {}",
        DNS_QUERY
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).unwrap())
            .collect::<Vec<_>>()
            .join(" ")
    );
    assert_eq!(
        stdout(&plain),
        format!(
            "1: {line}\n  dns question: example.test. type=1 class=1\n2: {line}\n  dns question: example.test. type=1 class=1\n"
        )
    );

    let tree = run_success(&["read", path, "--dissect", "--tree", "--frames", "2"]);
    let text = stdout(&tree);
    let lines = text.lines().collect::<Vec<_>>();
    assert_eq!(lines[0], format!("2: {line}"));
    assert_eq!(lines[1], "2: 0: ipv4");
    assert!(lines.contains(&"  checksum = 63151 (derived)"), "{text}");
    assert!(lines.contains(&"      name = \"example.test.\""), "{text}");
    assert!(lines.iter().all(|line| !line.starts_with("1: ")), "{text}");
    assert!(!text.contains("dns question:"));

    // The budget spans every frame in the run.
    let both = run_success(&["read", path, "--dissect", "--tree"]);
    let tree_bytes = stdout(&both)
        .lines()
        .filter(|line| !line.contains("dlt=") && !line.contains("dns question"))
        .map(|line| line.len() + 1)
        .sum::<usize>();
    let exact = tree_bytes.to_string();
    run_success(&[
        "read",
        path,
        "--dissect",
        "--tree",
        "--max-tree-bytes",
        &exact,
    ]);
    let short = (tree_bytes - 1).to_string();
    let limited = run(&[
        "read",
        path,
        "--dissect",
        "--tree",
        "--max-tree-bytes",
        &short,
    ]);
    assert_eq!(limited.status.code(), Some(6));
    assert!(stderr(&limited).contains("policy.tree_output_limit"));
}

#[test]
fn read_tree_requires_dissect_and_text_output() {
    let capture = write_pcap_hex(&[DNS_QUERY]);
    let path = path_text(capture.path());
    for arguments in [
        vec!["read", path, "--tree"],
        vec!["--output", "ndjson", "read", path, "--dissect", "--tree"],
        vec!["--output", "hex", "read", path, "--tree"],
        vec!["read", path, "--field", "ip.src", "--tree"],
    ] {
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        if !arguments.contains(&"ndjson") {
            assert!(output.stdout.is_empty(), "{arguments:?}");
        }
    }
}
