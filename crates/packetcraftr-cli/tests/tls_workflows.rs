// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contracts for the `tls` command and the `--tls-port` remap it shares with
//! `read` and `dissect`.

use std::path::PathBuf;

mod support;
#[path = "support/tls_capture.rs"]
mod tls_capture;

use support::{assert_contiguous, parse_json, parse_ndjson, path_text, run, run_success};
use tls_capture::{Handshake, client_hello_frame_hex, write_capture, write_capture_with_udp_443};

/// The capture published for the README and `--help` examples.
fn published_capture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/captures/tls-handshake.pcapng")
}

fn text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn the_published_capture_assembles_one_complete_session_in_every_format() {
    let capture = published_capture();
    let path = path_text(&capture);

    let plain = run_success(&["tls", path]);
    let lines = text(&plain);
    let mut lines = lines.lines();
    let session = lines.next().expect("one session line");
    assert_eq!(
        session,
        "session=0 stream=tcp:0 client=192.0.2.1:54321 server=198.51.100.2:443 \
         status=complete sni=api.example.test version=TLS1.3 \
         cipher=0x1301(TLS_AES_128_GCM_SHA256) group=x25519 alpn=h2,http/1.1 \
         selected_alpn=none ja3=54e2a2e989457808c77e4464d9361826 \
         ja4=t13d0406h2_77f0cd3447db_5d4d534e3685 frames=4..5 rtt_ms=24.000"
    );
    let summary = lines.next().expect("one summary line");
    assert!(
        summary.starts_with("tls sessions=1 selected=1"),
        "{summary}"
    );
    assert!(summary.contains("complete=1"), "{summary}");
    assert!(summary.contains("tcp_streams=1"), "{summary}");
    assert_eq!(lines.next(), None, "text output is one line per session");
    assert!(
        !plain.stdout.windows(2).any(|window| window == b"\x1b["),
        "text output carries no terminal escapes"
    );

    let aggregate = parse_json(&run_success(&["--output", "json", "tls", path]));
    let sessions = aggregate["result"]["sessions"]
        .as_array()
        .expect("sessions is an array");
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0]["status"], "complete");
    assert_eq!(sessions[0]["client"]["sni"], "api.example.test");
    assert_eq!(sessions[0]["server"]["cipher_suite"], 0x1301);
    assert_eq!(
        sessions[0]["server"]["cipher_suite_name"],
        "TLS_AES_128_GCM_SHA256"
    );
    assert_eq!(sessions[0]["server"]["selected_version_name"], "TLS 1.3");
    assert_eq!(sessions[0]["server"]["key_share_group_name"], "x25519");
    assert!(
        sessions[0]["client"]["ja4"]
            .as_str()
            .is_some_and(|ja4| ja4.starts_with("t13d")),
        "{}",
        sessions[0]["client"]["ja4"]
    );
    assert_eq!(aggregate["result"]["summary"]["by_status"]["complete"], 1);

    let records = parse_ndjson(&run_success(&["--output", "ndjson", "tls", path]));
    assert_contiguous(&records);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["result"]["event"], "session");
    assert_eq!(records[0]["result"]["client"]["sni"], "api.example.test");
    assert_eq!(records[1]["result"]["event"], "complete");
    assert_eq!(records[1]["result"]["sessions"], 1);
}

#[test]
fn session_selectors_narrow_the_report_without_touching_assembly() {
    let capture = write_capture(&[
        Handshake::complete(40_000, 443, "api.example.test"),
        Handshake::complete(40_001, 8443, "files.example.test"),
        Handshake::unanswered(40_002, "silent.example.test"),
    ]);
    let path = path_text(capture.path());

    let all = parse_json(&run_success(&["--output", "json", "tls", path]));
    assert_eq!(all["result"]["summary"]["sessions"], 3);
    assert_eq!(all["result"]["summary"]["by_status"]["complete"], 2);
    assert_eq!(all["result"]["summary"]["by_status"]["client_only"], 1);
    assert_eq!(all["result"]["summary"]["tcp_streams"], 3);

    let selected = |arguments: &[&str]| {
        let mut invocation = vec!["--output", "json", "tls", path];
        invocation.extend_from_slice(arguments);
        let value = parse_json(&run_success(&invocation));
        value["result"]["sessions"]
            .as_array()
            .expect("sessions is an array")
            .iter()
            .map(|session| session["client"]["sni"].as_str().unwrap_or("").to_owned())
            .collect::<Vec<_>>()
    };

    assert_eq!(
        selected(&["--status", "complete", "--status", "client_only"]).len(),
        3,
        "repeated --status selects the union"
    );
    assert_eq!(
        selected(&["--status", "client_only"]),
        ["silent.example.test"]
    );
    assert_eq!(
        selected(&["--sni", "*.example.test"]).len(),
        3,
        "a leading wildcard matches every documentation name"
    );
    assert_eq!(selected(&["--sni", "api*"]), ["api.example.test"]);
    assert_eq!(selected(&["--sni", "*FILES*"]), ["files.example.test"]);
    assert_eq!(
        selected(&["--sni", "api.example.test"]),
        ["api.example.test"]
    );
    assert!(selected(&["--sni", "absent*"]).is_empty());
    assert_eq!(selected(&["--server-port", "8443"]), ["files.example.test"]);
    assert_eq!(selected(&["--stream", "tcp:1"]), ["files.example.test"]);

    // The stream selector is the one selector pushed down to the frames, so
    // the counters it reports are the filtered ones.
    let scoped = parse_json(&run_success(&[
        "--output", "json", "tls", path, "--stream", "tcp:1",
    ]));
    assert_eq!(scoped["result"]["summary"]["tcp_streams"], 1);
    assert_eq!(scoped["result"]["summary"]["frames_read"], 20);
    assert_eq!(scoped["result"]["summary"]["frames_matched"], 7);
}

#[test]
fn a_capture_without_tls_says_what_it_saw_and_where_to_look() {
    let capture = write_capture(&[Handshake::plain(40_000, 443)]);
    let path = path_text(capture.path());

    let output = run_success(&["tls", path]);
    let rendered = text(&output);
    assert!(
        rendered.contains(
            "no TLS sessions assembled: 6 frame(s) read, 6 matched, 1 TCP conversation(s)"
        ),
        "{rendered}"
    );
    assert!(
        rendered.contains("bound to ports 443,465,636,853,993,995,8443 (add --tls-port PORT"),
        "{rendered}"
    );
    assert!(rendered.contains("hint: no ClientHello"), "{rendered}");
    assert!(rendered.contains("tls sessions=0"), "{rendered}");

    let aggregate = parse_json(&run_success(&["--output", "json", "tls", path]));
    assert_eq!(
        aggregate["result"]["sessions"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(aggregate["result"]["summary"]["tcp_streams"], 1);
}

#[test]
fn an_extra_tls_port_reaches_the_per_frame_view_that_assembly_never_needed() {
    let capture = write_capture(&[Handshake::complete(40_000, 4433, "api.example.test")]);
    let path = path_text(capture.path());

    // Assembly reads every TCP stream, so the session is found either way.
    for arguments in [
        vec!["--output", "json", "tls", path],
        vec!["--output", "json", "tls", path, "--tls-port", "4433"],
    ] {
        let assembled = parse_json(&run_success(&arguments));
        let sessions = assembled["result"]["sessions"]
            .as_array()
            .expect("sessions is an array");
        assert_eq!(sessions.len(), 1, "{arguments:?}");
        assert_eq!(sessions[0]["status"], "complete");
        assert_eq!(sessions[0]["server_endpoint"]["port"], 4433);
    }

    let per_frame = run_success(&[
        "read",
        path,
        "--dissect",
        "--tls-port",
        "4433",
        "--filter",
        "tls",
    ]);
    let rendered = text(&per_frame);
    assert!(rendered.contains("tls"), "{rendered}");
    assert_eq!(
        rendered.lines().count(),
        2,
        "only the two hello frames carry a tls layer: {rendered}"
    );

    let without_remap = run_success(&["read", path, "--dissect", "--filter", "tls"]);
    assert!(
        text(&without_remap).is_empty(),
        "the default port list leaves 4433 raw"
    );
}

#[test]
fn selector_failures_exit_two_and_list_what_is_accepted() {
    let capture = write_capture(&[Handshake::complete(40_000, 443, "api.example.test")]);
    let path = path_text(capture.path());

    let cases: &[(&[&str], &str)] = &[
        (
            &["--stream", "udp:3"],
            "TLS sessions are assembled from TCP streams only",
        ),
        (&["--stream", "tcp:x"], "expected tcp:INDEX or udp:INDEX"),
        (&["--stream", "nonsense"], "expected tcp:INDEX or udp:INDEX"),
        (&["--status", "bogus"], "possible values"),
        (&["--sni", "a*b*c"], "only at the start"),
        (&["--stream", "tcp:9"], "not present (0..1)"),
    ];
    for (arguments, expected) in cases {
        let mut invocation = vec!["tls", path];
        invocation.extend_from_slice(arguments);
        let output = run(&invocation);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        let rendered = String::from_utf8_lossy(&output.stderr);
        assert!(rendered.contains(expected), "{arguments:?}: {rendered}");
    }

    let statuses = run(&["tls", path, "--status", "bogus"]);
    let rendered = String::from_utf8_lossy(&statuses.stderr);
    for status in [
        "complete",
        "client_only",
        "retry",
        "alert",
        "malformed",
        "gap",
        "truncated",
    ] {
        assert!(rendered.contains(status), "{rendered}");
    }
}

#[test]
fn a_capture_with_no_tcp_at_all_names_the_absence_rather_than_a_range() {
    let capture = write_capture(&[]);
    let path = path_text(capture.path());
    let output = run(&["tls", path, "--stream", "tcp:0"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("the capture has no TCP streams"),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn the_retention_ceiling_reports_what_it_left_out() {
    let capture = write_capture(&[
        Handshake::complete(40_000, 443, "api.example.test"),
        Handshake::complete(40_001, 443, "files.example.test"),
        Handshake::complete(40_002, 443, "www.example.test"),
    ]);
    let path = path_text(capture.path());

    let aggregate = parse_json(&run_success(&[
        "--output",
        "json",
        "tls",
        path,
        "--max-tls-sessions",
        "2",
    ]));
    assert_eq!(
        aggregate["result"]["sessions"].as_array().map(Vec::len),
        Some(2)
    );
    assert_eq!(aggregate["result"]["summary"]["sessions_selected"], 3);
    assert_eq!(aggregate["result"]["summary"]["sessions_omitted"], 1);

    // NDJSON streams instead of retaining, so the ceiling never applies.
    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "tls",
        path,
        "--max-tls-sessions",
        "2",
    ]));
    assert_eq!(records.len(), 4);
    assert_eq!(records[3]["result"]["sessions_omitted"], 0);

    // Text writes each session as it completes, so it omits none either.
    let rendered = text(&run_success(&["tls", path, "--max-tls-sessions", "2"]));
    let lines = rendered.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 4, "{rendered}");
    for sni in ["api.example.test", "files.example.test", "www.example.test"] {
        assert!(
            lines
                .iter()
                .any(|line| line.contains(&format!("sni={sni} "))),
            "{rendered}"
        );
    }
    assert!(
        lines[3].contains("sessions=3 selected=3 omitted=0"),
        "{rendered}"
    );
}

#[test]
fn selectors_that_keep_nothing_say_so_without_claiming_the_capture_has_no_tls() {
    let capture = write_capture(&[
        Handshake::complete(40_000, 443, "api.example.test"),
        Handshake::complete(40_001, 443, "files.example.test"),
    ]);
    let path = path_text(capture.path());

    let rendered = text(&run_success(&["tls", path, "--sni", "absent.example.test"]));
    let lines = rendered.lines().collect::<Vec<_>>();
    assert_eq!(
        lines.first().copied(),
        Some("no session matched the selectors (2 assembled)"),
        "{rendered}"
    );
    assert!(
        !rendered.contains("no TLS sessions assembled"),
        "{rendered}"
    );
    assert!(!rendered.contains("hint: no ClientHello"), "{rendered}");
    assert!(
        lines[1].starts_with("tls sessions=2 selected=0 omitted=0"),
        "{rendered}"
    );

    // Nothing assembled at all is the other answer, and it keeps its hint.
    let empty = text(&run_success(&["tls", path_text(write_capture(&[]).path())]));
    assert!(empty.contains("no TLS sessions assembled"), "{empty}");
    assert!(empty.contains("hint: no ClientHello"), "{empty}");
}

#[test]
fn the_empty_report_lists_the_ports_the_per_frame_layer_actually_binds() {
    let capture = write_capture_with_udp_443(&[Handshake::plain(40_000, 443)], 2);
    let path = path_text(capture.path());

    let rendered = text(&run_success(&["tls", path, "--tls-port", "4433"]));
    assert!(
        rendered.contains("bound to ports 443,465,636,853,993,995,4433,8443 (add --tls-port PORT"),
        "{rendered}"
    );
    assert!(
        rendered.contains("note: 2 UDP frame(s) on port 443 are most likely QUIC"),
        "{rendered}"
    );
    assert!(rendered.contains("udp_443_frames=2"), "{rendered}");
}

#[test]
fn dissect_reads_a_remapped_port_as_tls_only_when_the_flag_is_given() {
    let hex = client_hello_frame_hex(4433, "api.example.test");

    let remapped = text(&run_success(&[
        "dissect",
        "--hex",
        &hex,
        "--link-type",
        "228",
        "--tls-port",
        "4433",
    ]));
    assert!(remapped.contains("2: tls"), "{remapped}");

    let plain = text(&run_success(&[
        "dissect",
        "--hex",
        &hex,
        "--link-type",
        "228",
    ]));
    assert!(!plain.contains("tls"), "{plain}");
    assert!(plain.contains("1: tcp"), "{plain}");
}

#[test]
fn limit_failures_are_reported_before_any_capture_is_read() {
    let missing = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("does-not-exist.pcapng");
    for arguments in [
        vec!["tls", path_text(&missing), "--max-tls-sessions", "0"],
        vec!["tls", path_text(&missing), "--max-tls-buffer-bytes", "0"],
    ] {
        let output = run(&arguments);
        assert!(!output.status.success(), "{arguments:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("non-zero"),
            "{arguments:?}: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // The floor is the per-direction buffer, and the flag that set it is the
    // one named back.
    let floored = run(&["tls", path_text(&missing), "--max-tls-buffer-bytes", "1024"]);
    assert_eq!(floored.status.code(), Some(2));
    let rendered = String::from_utf8_lossy(&floored.stderr);
    assert!(
        rendered.contains("--max-tls-buffer-bytes=1024"),
        "{rendered}"
    );
    assert!(
        rendered.contains(&packetcraftr::core::analysis::tls::MAX_DIRECTION_BUFFER.to_string()),
        "{rendered}"
    );
    assert!(
        !rendered.contains("max_direction_bytes"),
        "the internal field name never reaches the user: {rendered}"
    );
}
