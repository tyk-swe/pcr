// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `verify-forwarding` process contracts: verdicts, exit statuses, terminal
//! records, and rule rejection.

#[path = "support/process.rs"]
mod process_support;
mod support;

use std::io::Write;

use process_support::{decode_hex, run_with_stdin};
use support::{parse_json, parse_ndjson, path_text, run, run_success};

/// 192.0.2.1:12345 → 198.51.100.2:9 UDP carrying "hello", TTL 64.
const UDP_CLIENT: &str = "450000210000000040118e95c0000201c633640230390009000d9f8868656c6c6f";
/// `UDP_CLIENT` forwarded: TTL decremented to 63 with the checksum updated.
const UDP_CLIENT_FORWARDED: &str =
    "45000021000000003f118f95c0000201c633640230390009000d9f8868656c6c6f";
/// 198.51.100.2:9 → 192.0.2.1:12345 UDP carrying "world".
const UDP_SERVER: &str = "450000210000000040118e95c6336402c000020100093039000d957e776f726c64";
/// A TCP segment; never matches a `udp` selection filter.
const TCP_CLIENT: &str =
    "4500002b0000000040068e96c0000201c63364023039005000000001000000005002ffffb7b80000676574";

fn write_capture(frames: &[&str]) -> tempfile::NamedTempFile {
    let frames = frames.iter().copied().map(decode_hex).collect::<Vec<_>>();
    write_capture_bytes(&frames)
}

fn write_capture_bytes(frames: &[Vec<u8>]) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("temporary capture must open");
    file.write_all(&[
        0xd4, 0xc3, 0xb2, 0xa1, // little-endian microsecond PCAP
        2, 0, 4, 0, // version 2.4
        0, 0, 0, 0, 0, 0, 0, 0, // timezone and timestamp accuracy
        0xff, 0xff, 0, 0, // snap length
        228, 0, 0, 0, // DLT_IPV4
    ])
    .expect("global header must write");
    for (index, bytes) in frames.iter().enumerate() {
        let seconds = u32::try_from(index + 1).expect("fixture index fits u32");
        let length = u32::try_from(bytes.len()).expect("fixture frame fits u32");
        file.write_all(&seconds.to_le_bytes())
            .expect("timestamp seconds must write");
        file.write_all(&250_000_u32.to_le_bytes())
            .expect("timestamp fraction must write");
        file.write_all(&length.to_le_bytes())
            .expect("captured length must write");
        file.write_all(&length.to_le_bytes())
            .expect("original length must write");
        file.write_all(bytes).expect("frame bytes must write");
    }
    file.flush().expect("capture must flush");
    file
}

/// A capture whose single record retains fewer bytes than the wire length:
/// the UDP datagram is absent, so the frame is truncated evidence.
fn write_snaplen_truncated_capture() -> tempfile::NamedTempFile {
    let bytes = decode_hex(UDP_CLIENT);
    let captured = 20_u32; // IPv4 header only.
    let mut file = tempfile::NamedTempFile::new().expect("temporary capture must open");
    file.write_all(&[
        0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 228, 0, 0, 0,
    ])
    .expect("global header must write");
    file.write_all(&1_u32.to_le_bytes())
        .expect("timestamp seconds must write");
    file.write_all(&250_000_u32.to_le_bytes())
        .expect("timestamp fraction must write");
    file.write_all(&captured.to_le_bytes())
        .expect("captured length must write");
    file.write_all(&(bytes.len() as u32).to_le_bytes())
        .expect("original length must write");
    file.write_all(&bytes[..captured as usize])
        .expect("frame bytes must write");
    file.flush().expect("capture must flush");
    file
}

fn verify(ingress: &tempfile::NamedTempFile, egress: &tempfile::NamedTempFile) -> Vec<String> {
    vec![
        "verify-forwarding".to_owned(),
        path_text(ingress.path()).to_owned(),
        path_text(egress.path()).to_owned(),
    ]
}

#[test]
fn exact_correspondence_passes_with_zero_status() {
    let ingress = write_capture(&[UDP_CLIENT, UDP_SERVER]);
    let egress = write_capture(&[UDP_CLIENT, UDP_SERVER]);
    let mut args = verify(&ingress, &egress);
    args.extend(["--identity".to_owned(), "raw.bytes".to_owned()]);

    let output = run_success(&args.iter().map(String::as_str).collect::<Vec<_>>());
    let stdout = String::from_utf8(output.stdout).expect("text output is UTF-8");
    assert!(stdout.contains("verdict: pass"), "{stdout}");
    assert!(stdout.contains("matches: 2 unique"), "{stdout}");
    assert!(
        stdout.contains("unmatched: 0 ingress, 0 egress"),
        "{stdout}"
    );
}

#[test]
fn a_preserved_field_mismatch_is_a_concrete_failure() {
    // Forwarding decremented the TTL; ipv4.identification still pairs the
    // observations so the violated preservation names both sides.
    let ingress = write_capture(&[UDP_CLIENT]);
    let egress = write_capture(&[UDP_CLIENT_FORWARDED]);
    let mut args = verify(&ingress, &egress);
    args.extend([
        "--identity".to_owned(),
        "ipv4.identification".to_owned(),
        "--preserve".to_owned(),
        "ipv4.ttl".to_owned(),
    ]);

    let output = run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("verdict: fail"), "{stdout}");
    assert!(stdout.contains("preserve ipv4.ttl"), "{stdout}");
    assert!(stdout.contains("64"), "{stdout}");
    assert!(stdout.contains("63"), "{stdout}");
}

#[test]
fn missing_egress_is_inconclusive_not_loss() {
    let ingress = write_capture(&[UDP_CLIENT, UDP_SERVER]);
    let egress = write_capture(&[UDP_CLIENT]);

    let mut args = vec!["--output".to_owned(), "json".to_owned()];
    args.extend(verify(&ingress, &egress));
    args.extend(["--identity".to_owned(), "raw.bytes".to_owned()]);
    let output = run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(output.status.code(), Some(1));

    let document = parse_json(&output);
    let result = &document["result"];
    assert_eq!(result["verdict"], "inconclusive");
    assert_eq!(result["summary"]["ingress_only"], 1);
    assert_eq!(result["unmatched"]["ingress"].as_array().unwrap().len(), 1);
    assert_eq!(result["unmatched"]["ingress"][0]["frame"], 2);
    // Missing egress is reported as unmatched evidence, never as a drop.
    let text = document.to_string();
    assert!(!text.contains("dropped"), "{text}");
}

#[test]
fn extra_egress_is_inconclusive_not_duplication() {
    let ingress = write_capture(&[UDP_CLIENT]);
    let egress = write_capture(&[UDP_CLIENT, UDP_SERVER]);

    let mut args = vec!["--output".to_owned(), "json".to_owned()];
    args.extend(verify(&ingress, &egress));
    args.extend(["--identity".to_owned(), "raw.bytes".to_owned()]);
    let output = run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(output.status.code(), Some(1));

    let result = parse_json(&output)["result"].clone();
    assert_eq!(result["verdict"], "inconclusive");
    assert_eq!(result["summary"]["egress_only"], 1);
    assert_eq!(result["unmatched"]["egress"][0]["frame"], 2);
}

#[test]
fn repeated_identity_stays_ambiguous_and_unpaired() {
    let ingress = write_capture(&[UDP_CLIENT, UDP_CLIENT]);
    let egress = write_capture(&[UDP_CLIENT]);

    let mut args = vec!["--output".to_owned(), "json".to_owned()];
    args.extend(verify(&ingress, &egress));
    args.extend(["--identity".to_owned(), "raw.bytes".to_owned()]);
    let output = run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(output.status.code(), Some(1));

    let result = parse_json(&output)["result"].clone();
    assert_eq!(result["verdict"], "inconclusive");
    assert_eq!(result["summary"]["unique_matches"], 0);
    assert_eq!(result["summary"]["ambiguous_groups"], 1);
    let group = &result["ambiguous"][0];
    assert_eq!(group["ingress_total"], 2);
    assert_eq!(group["egress_total"], 1);
    assert_eq!(group["ingress_indistinguishable"], true);
    assert!(result["matches"].as_array().unwrap().is_empty());
}

#[test]
fn per_side_filters_select_independently() {
    // The ingress filter selects only UDP; without it the extra TCP frame
    // would be unmatched evidence on the ingress side.
    let ingress = write_capture(&[UDP_CLIENT, TCP_CLIENT]);
    let egress = write_capture(&[UDP_CLIENT]);

    let mut args = vec!["--output".to_owned(), "json".to_owned()];
    args.extend(verify(&ingress, &egress));
    args.extend([
        "--identity".to_owned(),
        "raw.bytes".to_owned(),
        "--ingress-filter".to_owned(),
        "udp".to_owned(),
    ]);
    let output = run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let result = parse_json(&output)["result"].clone();
    assert_eq!(result["verdict"], "pass");
    assert_eq!(result["captures"]["ingress"]["read"], 2);
    assert_eq!(result["captures"]["ingress"]["selected"], 1);
    assert_eq!(result["captures"]["egress"]["selected"], 1);
}

#[test]
fn an_empty_selection_never_passes() {
    let ingress = write_capture(&[UDP_CLIENT]);
    let egress = write_capture(&[UDP_CLIENT]);

    let mut args = vec!["--output".to_owned(), "json".to_owned()];
    args.extend(verify(&ingress, &egress));
    args.extend([
        "--identity".to_owned(),
        "raw.bytes".to_owned(),
        "--egress-filter".to_owned(),
        "icmp".to_owned(),
    ]);
    let output = run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(output.status.code(), Some(1));

    let result = parse_json(&output)["result"].clone();
    assert_eq!(result["verdict"], "inconclusive");
    assert_eq!(result["captures"]["egress"]["selected"], 0);
    // The unpaired ingress observations still surface as evidence.
    assert_eq!(result["summary"]["ingress_only"], 1);
}

#[test]
fn snaplen_truncated_evidence_is_explicitly_inconclusive() {
    let ingress = write_capture(&[UDP_CLIENT]);
    let egress = write_snaplen_truncated_capture();

    let mut args = vec!["--output".to_owned(), "json".to_owned()];
    args.extend(verify(&ingress, &egress));
    args.extend(["--identity".to_owned(), "raw.bytes".to_owned()]);
    let output = run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(output.status.code(), Some(1));

    let result = parse_json(&output)["result"].clone();
    assert_eq!(result["verdict"], "inconclusive");
    // The truncated record fails dissection: unkeyed and incomplete.
    assert_eq!(result["captures"]["egress"]["incomplete"], 1);
    assert_eq!(result["captures"]["egress"]["unkeyed"], 1);
    assert_eq!(result["unkeyed"]["egress"][0]["evidence"]["frame"], 1);
}

#[test]
fn an_expectation_violation_is_attributable_failure() {
    let ingress = write_capture(&[UDP_CLIENT]);
    let egress = write_capture(&[UDP_CLIENT]);

    let mut args = vec!["--output".to_owned(), "json".to_owned()];
    args.extend(verify(&ingress, &egress));
    args.extend([
        "--identity".to_owned(),
        "raw.bytes".to_owned(),
        "--expect".to_owned(),
        "ipv4.destination=192.0.2.99".to_owned(),
    ]);
    let output = run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(output.status.code(), Some(1));

    let result = parse_json(&output)["result"].clone();
    assert_eq!(result["verdict"], "fail");
    assert_eq!(result["summary"]["checks_violated"], 1);
    let violation = &result["violations"][0];
    assert_eq!(violation["check"]["kind"], "expect");
    assert_eq!(violation["check"]["field"], "ipv4.destination");
    assert_eq!(violation["check"]["value"], "192.0.2.99");
    assert_eq!(violation["actual"]["value"], "198.51.100.2");
    assert_eq!(violation["egress"]["frame"], 1);
}

#[test]
fn satisfied_expectation_and_preservation_pass() {
    // The forwarded frame kept its destination and total length; the changed
    // TTL is not a declared rule, so nothing is violated.
    let ingress = write_capture(&[UDP_CLIENT]);
    let egress = write_capture(&[UDP_CLIENT_FORWARDED]);
    let mut args = vec!["--output".to_owned(), "json".to_owned()];
    args.extend(verify(&ingress, &egress));
    args.extend([
        "--identity".to_owned(),
        "ipv4.identification".to_owned(),
        "--preserve".to_owned(),
        "ipv4.total_length".to_owned(),
        "--expect".to_owned(),
        "ipv4.destination=198.51.100.2".to_owned(),
    ]);
    let output = run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let result = parse_json(&output)["result"].clone();
    assert_eq!(result["verdict"], "pass");
    assert_eq!(result["summary"]["checks_evaluated"], 2);
    assert_eq!(result["summary"]["checks_satisfied"], 2);
}

#[test]
fn detail_lists_are_bounded_and_omissions_counted() {
    let frames: Vec<Vec<u8>> = (0..4_u8)
        .map(|index| {
            // Distinct payload bytes give every frame a unique raw identity.
            let mut bytes = decode_hex(UDP_CLIENT);
            *bytes.last_mut().expect("UDP payload") = index;
            bytes
        })
        .collect();
    let ingress = write_capture_bytes(&frames);
    let egress = write_capture(&[UDP_SERVER]);

    let mut args = vec!["--output".to_owned(), "json".to_owned()];
    args.extend(verify(&ingress, &egress));
    args.extend([
        "--identity".to_owned(),
        "raw.bytes".to_owned(),
        "--max-details".to_owned(),
        "1".to_owned(),
    ]);
    let output = run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(output.status.code(), Some(1));

    let document = parse_json(&output);
    let result = &document["result"];
    // The summary counts complete evidence; the lists are bounded samples.
    assert_eq!(result["summary"]["ingress_only"], 4);
    assert_eq!(result["summary"]["egress_only"], 1);
    assert_eq!(result["unmatched"]["ingress"].as_array().unwrap().len(), 1);
    assert_eq!(result["unmatched"]["egress"].as_array().unwrap().len(), 1);
    assert_eq!(result["omitted"]["unmatched_ingress"], 3);
    assert_eq!(result["omitted"]["unmatched_egress"], 0);
    assert!(
        document["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["code"] == "verify_forwarding.details_omitted"),
        "{document}"
    );
}

#[test]
fn ndjson_publishes_exactly_one_complete_record() {
    let ingress = write_capture(&[UDP_CLIENT]);
    let egress = write_capture(&[UDP_CLIENT]);

    let mut args = vec!["--output".to_owned(), "ndjson".to_owned()];
    args.extend(verify(&ingress, &egress));
    args.extend(["--identity".to_owned(), "raw.bytes".to_owned()]);
    let output = run_success(&args.iter().map(String::as_str).collect::<Vec<_>>());

    let records = parse_ndjson(&output);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["event"], "complete");
    assert_eq!(records[0]["result"]["verdict"], "pass");
}

#[test]
fn a_fail_verdict_ndjson_still_terminates_with_complete() {
    let ingress = write_capture(&[UDP_CLIENT]);
    let egress = write_capture(&[UDP_CLIENT_FORWARDED]);

    let mut args = vec!["--output".to_owned(), "ndjson".to_owned()];
    args.extend(verify(&ingress, &egress));
    args.extend([
        "--identity".to_owned(),
        "ipv4.identification".to_owned(),
        "--preserve".to_owned(),
        "ipv4.ttl".to_owned(),
    ]);
    let output = run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(output.status.code(), Some(1));

    // A completed report is one terminal success record carrying the verdict;
    // the non-zero exit status lives on the process, not a second record.
    let records = parse_ndjson(&output);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["event"], "complete");
    assert_eq!(records[0]["result"]["verdict"], "fail");
}

#[test]
fn simultaneous_stdin_is_rejected() {
    let capture = write_capture(&[UDP_CLIENT]);
    let bytes = std::fs::read(capture.path()).expect("capture bytes");
    let output = run_with_stdin(
        &["verify-forwarding", "-", "-", "--identity", "raw.bytes"],
        &bytes,
    );
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cli.input_source"), "{stderr}");
    assert!(stderr.contains("cannot both read stdin"), "{stderr}");
}

#[test]
fn stdin_may_serve_one_side() {
    let ingress = write_capture(&[UDP_CLIENT]);
    let egress = write_capture(&[UDP_CLIENT]);
    let bytes = std::fs::read(ingress.path()).expect("capture bytes");

    let output = run_with_stdin(
        &[
            "verify-forwarding",
            "-",
            path_text(egress.path()),
            "--identity",
            "raw.bytes",
        ],
        &bytes,
    );
    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("text output is UTF-8");
    assert!(stdout.contains("verdict: pass"), "{stdout}");
}

#[test]
fn capture_local_identity_fields_are_rejected() {
    let ingress = write_capture(&[UDP_CLIENT]);
    let egress = write_capture(&[UDP_CLIENT]);

    let output = run(&[
        "verify-forwarding",
        path_text(ingress.path()),
        path_text(egress.path()),
        "--identity",
        "frame.number",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cli.verify_rule"), "{stderr}");
    assert!(stderr.contains("frame.number"), "{stderr}");
}

#[test]
fn malformed_expectations_are_rejected_before_input_is_read() {
    let output = run(&[
        "verify-forwarding",
        "does-not-exist.pcap",
        "also-absent.pcap",
        "--identity",
        "raw.bytes",
        "--expect",
        "no-equals-sign",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cli.verify_rule"), "{stderr}");
    // The rule fails before the missing input files are opened.
    assert!(!stderr.contains("does-not-exist"), "{stderr}");
}

#[test]
fn an_unsupported_output_format_is_rejected() {
    let ingress = write_capture(&[UDP_CLIENT]);
    let egress = write_capture(&[UDP_CLIENT]);

    let output = run(&[
        "--output",
        "csv",
        "verify-forwarding",
        path_text(ingress.path()),
        path_text(egress.path()),
        "--identity",
        "raw.bytes",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cli.output_format"), "{stderr}");
}
