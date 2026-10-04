// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Hexadecimal text input, shared link-type names, and the field tree view of `dissect` and
// `read --dissect`.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[path = "common/capture.rs"]
mod capture_support;
mod common;
#[path = "common/process.rs"]
mod process_support;

use common::{path_text, run};
use process_support::{run_with_stdin, run_with_stdin_writer};

/// 192.0.2.1:40000 to 192.0.2.2:53 carrying a DNS question for example.test.
const DNS_QUERY: &str = "4500003a000000004011f6afc0000201c00002029c4000350026a7a1\
                         000000000001000000000000076578616d706c6504746573740000010001";

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
fn hex_text_decoded_bounded_by_pkt_budget() {
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

    let refused_tail = AtomicBool::new(false);
    let piped = run_with_stdin_writer(
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
        |mut stdin, input, child_exited| {
            // The bounded reader rejects this prefix without needing EOF. Hold
            // the unused tail until the child exits to exercise its refusal
            // independently of scheduling and the OS pipe's capacity.
            stdin.write_all(&input[..4096 + 4 * 8 + 1])?;
            child_exited
                .recv_timeout(Duration::from_secs(5))
                .map_err(io::Error::other)?;
            let result = stdin.write_all(&input[4096 + 4 * 8 + 1..]);
            refused_tail.store(
                result
                    .as_ref()
                    .is_err_and(|error| error.kind() == io::ErrorKind::BrokenPipe),
                Ordering::Relaxed,
            );
            result
        },
    );
    assert_eq!(piped.status.code(), Some(6));
    assert!(stderr(&piped).contains("frame hex text input exceeds"));
    assert!(piped.stdout.is_empty());
    assert!(refused_tail.load(Ordering::Relaxed));

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
fn stdin_write_fails_errors_failed_reject_input() {
    let refused_input = AtomicBool::new(false);
    let successful_child = std::panic::catch_unwind(|| {
        run_with_stdin_writer(&["--help"], b"unused", |mut stdin, input, child_exited| {
            child_exited
                .recv_timeout(Duration::from_secs(5))
                .map_err(io::Error::other)?;
            let result = stdin.write_all(input);
            refused_input.store(
                result
                    .as_ref()
                    .is_err_and(|error| error.kind() == io::ErrorKind::BrokenPipe),
                Ordering::Relaxed,
            );
            result
        })
    });
    assert!(refused_input.load(Ordering::Relaxed));
    assert_stdin_writer_panic(successful_child);

    let other_write_error = std::panic::catch_unwind(|| {
        run_with_stdin_writer(&["--invalid-test-option"], b"unused", |_, _, _| {
            Err(io::Error::other("injected stdin write failure"))
        })
    });
    let message = assert_stdin_writer_panic(other_write_error);
    assert!(
        message.contains("injected stdin write failure"),
        "{message}"
    );
}

fn assert_stdin_writer_panic(result: std::thread::Result<std::process::Output>) -> String {
    let panic = result.expect_err("the stdin writer failure must remain an error");
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .expect("the stdin writer panic must have a message");
    assert!(message.contains("stdin must accept input"), "{message}");
    message.to_owned()
}

#[test]
fn bad_hex_text_keeps_inline_usage_errors() {
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
    for blank in ["", "\n  \n", "0x", " 0x\n", "\t0X\r\n", " : - "] {
        let inline = run(&["dissect", "--link-type", "ipv4", "--hex", blank]);
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
        for output in [&inline, &piped, &from_file] {
            assert_eq!(output.status.code(), Some(2), "{blank:?}");
            assert!(stderr(output).contains("cli.input_source"), "{blank:?}");
            assert!(stderr(output).contains("frame hex text input is required"));
            assert!(output.stdout.is_empty());
        }
    }
}
