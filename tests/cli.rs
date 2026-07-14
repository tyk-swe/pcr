// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use packetcraftr::{
    capture::{Format as CaptureFormat, Frame, LinkType, Reader, Writer},
    packet::{
        build::{Builder, Context as BuildContext, Options as BuildOptions},
        expression::{Options as ExpressionOptions, parse as parse_packet_expression},
    },
    protocol::builtin::registry as default_registry,
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
}

fn normalize_cli_text(bytes: &[u8]) -> String {
    let text = String::from_utf8(bytes.to_vec())
        .unwrap()
        .replace("\r\n", "\n");
    text.split('\n')
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
}

fn temp_path(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "packetcraftr-{label}-{}-{suffix}-{sequence}.bin",
        std::process::id()
    ))
}

fn write_capture(frames: &[&[u8]], malformed_tail: bool) -> PathBuf {
    let mut writer = Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
    for (index, bytes) in frames.iter().enumerate() {
        let frame = Frame::new(
            UNIX_EPOCH + std::time::Duration::from_secs(index as u64),
            LinkType::ETHERNET,
            bytes.to_vec(),
        )
        .unwrap();
        writer.write_frame(&frame).unwrap();
    }
    let mut bytes = writer.into_inner();
    if malformed_tail {
        bytes.extend_from_slice(&[0_u8; 8]);
    }
    let path = temp_path("typed-output");
    std::fs::write(&path, bytes).unwrap();
    path
}

fn write_link_capture(link_type: LinkType, frames: &[&[u8]]) -> PathBuf {
    let mut writer = Writer::pcap(Vec::new(), link_type).unwrap();
    for (index, bytes) in frames.iter().enumerate() {
        writer
            .write_frame(
                &Frame::new(
                    UNIX_EPOCH + std::time::Duration::from_millis(index as u64 * 10),
                    link_type,
                    bytes.to_vec(),
                )
                .unwrap(),
            )
            .unwrap();
    }
    let path = temp_path("link-capture");
    std::fs::write(&path, writer.into_inner()).unwrap();
    path
}

fn write_public_raw_capture() -> PathBuf {
    use std::sync::Arc;

    let registry = Arc::new(default_registry().unwrap());
    let packet = parse_packet_expression(
        "ipv4(src=192.0.2.1,dst=8.8.8.8,identification=1)/udp(sport=40000,dport=9)/raw(text=hi)",
        &registry,
        ExpressionOptions::default(),
    )
    .unwrap();
    let built = Builder::new(registry)
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    write_link_capture(LinkType::RAW, &[built.bytes.as_ref()])
}

fn decode_output_hex(output: &[u8]) -> Vec<u8> {
    let value = std::str::from_utf8(output).unwrap().trim();
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn cli_help_parse_error_and_version_match_the_committed_goldens() {
    const COMMANDS: &[&str] = &[
        "build",
        "dissect",
        "read",
        "interfaces",
        "plan",
        "send",
        "exchange",
        "capture",
        "replay",
        "scan",
        "traceroute",
        "dns",
        "fuzz",
        "routes",
    ];

    let mut sections = Vec::with_capacity(COMMANDS.len() + 1);
    for (label, arguments) in std::iter::once(("packetcraftr --help".to_owned(), vec!["--help"]))
        .chain(COMMANDS.iter().map(|command| {
            (
                format!("packetcraftr {command} --help"),
                vec![*command, "--help"],
            )
        }))
    {
        let output = binary().args(arguments).output().unwrap();
        assert!(output.status.success(), "{label}");
        assert!(output.stderr.is_empty(), "{label}");
        sections.push(format!(
            "===== {label} =====\n{}\n",
            normalize_cli_text(&output.stdout).trim_end()
        ));
    }
    assert_eq!(
        sections.join("\n"),
        normalize_cli_text(include_str!("golden/cli-help.txt").as_bytes())
    );

    let parse_error = binary()
        .args(["build", "--unknown-option"])
        .output()
        .unwrap();
    assert_eq!(parse_error.status.code(), Some(2));
    assert!(parse_error.stdout.is_empty());
    assert_eq!(
        normalize_cli_text(&parse_error.stderr),
        normalize_cli_text(include_str!("golden/cli-parse-error.txt").as_bytes())
    );

    let version = binary().arg("--version").output().unwrap();
    assert!(version.status.success());
    assert!(version.stderr.is_empty());
    assert_eq!(
        normalize_cli_text(&version.stdout),
        normalize_cli_text(include_str!("golden/cli-version.txt").as_bytes())
    );
}

#[test]
fn parse_error_output_detection_respects_the_end_of_options_marker() {
    let positional = binary()
        .args(["read", "--", "--output=json", "extra"])
        .output()
        .unwrap();
    assert_eq!(positional.status.code(), Some(2));
    assert!(positional.stdout.is_empty());
    assert!(!positional.stderr.is_empty());
    assert!(serde_json::from_slice::<serde_json::Value>(&positional.stderr).is_err());

    let option = binary()
        .args(["--output=json", "read", "--unknown-option"])
        .output()
        .unwrap();
    assert_eq!(option.status.code(), Some(2));
    assert!(option.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&option.stdout).unwrap();
    assert_eq!(value["error"]["kind"], "cli");

    let command_shaped_positional = binary()
        .args(["--output=json", "--", "scan"])
        .output()
        .unwrap();
    assert_eq!(command_shaped_positional.status.code(), Some(2));
    assert!(command_shaped_positional.stderr.is_empty());
    let value: serde_json::Value =
        serde_json::from_slice(&command_shaped_positional.stdout).unwrap();
    assert!(value["command"].is_null());
    assert_eq!(value["error"]["kind"], "cli");
}

#[test]
fn build_expression_emits_complete_frame_hex() {
    let output = binary()
        .args([
            "--output",
            "hex",
            "build",
            "--packet",
            "ipv4(src=192.0.2.1,dst=198.51.100.2)/udp(sport=12345,dport=9)/raw(text=hi)",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hex = String::from_utf8(output.stdout).unwrap();
    assert!(hex.trim().starts_with("45"));
    assert!(hex.trim().ends_with("6869"));
}

#[test]
fn exact_bytes_agree_across_json_raw_hex_ndjson_pcap_and_pcapng() {
    let expression = "raw(hex=0001027f80ffdeadbeef)";
    let raw = binary()
        .args(["--output", "raw", "build", "--packet", expression])
        .output()
        .unwrap();
    assert!(raw.status.success());
    let expected = raw.stdout;

    let json = binary()
        .args(["--output", "json", "build", "--packet", expression])
        .output()
        .unwrap();
    assert!(json.status.success());
    let aggregate: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(
        decode_output_hex(
            aggregate["result"]["bytes_hex"]
                .as_str()
                .unwrap()
                .as_bytes()
        ),
        expected
    );

    let hex = binary()
        .args(["--output", "hex", "build", "--packet", expression])
        .output()
        .unwrap();
    assert!(hex.status.success());
    assert_eq!(decode_output_hex(&hex.stdout), expected);

    let path = write_link_capture(LinkType::RAW, &[&expected]);
    let read_hex = binary()
        .args(["--output", "hex", "read"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(read_hex.status.success());
    assert_eq!(decode_output_hex(&read_hex.stdout), expected);

    let ndjson = binary()
        .args(["--output", "ndjson", "read"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(ndjson.status.success());
    let record: serde_json::Value = serde_json::from_slice(&ndjson.stdout).unwrap();
    assert_eq!(
        decode_output_hex(
            record["result"]["frame"]["bytes_hex"]
                .as_str()
                .unwrap()
                .as_bytes()
        ),
        expected
    );
    assert_eq!(
        record["result"]["frame"]["captured_length"],
        expected.len() as u64
    );
    assert_eq!(
        record["result"]["frame"]["original_length"],
        expected.len() as u64
    );

    for format in ["pcap", "pcapng"] {
        let output = binary()
            .args(["--output", format, "read"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{format}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut reader = Reader::new(std::io::Cursor::new(output.stdout)).unwrap();
        let frame = reader.next_frame().unwrap().unwrap();
        assert_eq!(frame.bytes.as_ref(), expected, "{format}");
        assert_eq!(frame.captured_length as usize, expected.len(), "{format}");
        assert_eq!(frame.original_length as usize, expected.len(), "{format}");
        assert!(reader.next_frame().unwrap().is_none(), "{format}");
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn packet_document_build_dissect_capture_read_pipeline_is_exact() {
    let document =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/documents/packet-ipv4-udp.json");
    let built = binary()
        .args(["--output", "raw", "build", "--packet-file"])
        .arg(&document)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    assert!(built.stderr.is_empty());
    assert!(!built.stdout.is_empty());

    let mut dissect = binary();
    dissect
        .args(["--output", "json", "dissect", "--link-type", "1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = dissect.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&built.stdout)
        .unwrap();
    let dissected = child.wait_with_output().unwrap();
    assert!(
        dissected.status.success(),
        "{}",
        String::from_utf8_lossy(&dissected.stderr)
    );
    assert!(dissected.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&dissected.stdout).unwrap();
    assert_eq!(value["schema"], "packetcraftr.output/v1");
    assert_eq!(value["status"], "success");
    assert_eq!(
        decode_output_hex(value["result"]["bytes_hex"].as_str().unwrap().as_bytes()),
        built.stdout
    );

    let frame = Frame::new(UNIX_EPOCH, LinkType::ETHERNET, built.stdout.clone()).unwrap();
    for format in [CaptureFormat::Pcap, CaptureFormat::PcapNg] {
        let mut writer = Writer::new(Vec::new(), format, LinkType::ETHERNET).unwrap();
        writer.write_frame(&frame).unwrap();
        let path = temp_path(&format!("document-pipeline-{format}"));
        std::fs::write(&path, writer.into_inner()).unwrap();

        let hex = binary()
            .args(["--output", "hex", "read"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            hex.status.success(),
            "{}: {}",
            format,
            String::from_utf8_lossy(&hex.stderr)
        );
        assert!(hex.stderr.is_empty());
        assert_eq!(decode_output_hex(&hex.stdout), built.stdout, "{format}");

        let ndjson = binary()
            .args(["--output", "ndjson", "read"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            ndjson.status.success(),
            "{}: {}",
            format,
            String::from_utf8_lossy(&ndjson.stderr)
        );
        assert!(ndjson.stderr.is_empty());
        let record: serde_json::Value = serde_json::from_slice(&ndjson.stdout).unwrap();
        assert_eq!(record["schema"], "packetcraftr.output/v1");
        assert_eq!(record["sequence"], 0);
        assert_eq!(
            decode_output_hex(
                record["result"]["frame"]["bytes_hex"]
                    .as_str()
                    .unwrap()
                    .as_bytes()
            ),
            built.stdout
        );
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn json_build_uses_versioned_success_envelope() {
    let output = binary()
        .args(["--output", "json", "build", "--packet", "raw(hex=deadbeef)"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "packetcraftr.output/v1");
    assert_eq!(value["command"], "build");
    assert_eq!(value["mode"], "aggregate");
    assert_eq!(value["status"], "success");
    assert_eq!(value["result"]["bytes_hex"], "deadbeef");
    assert!(value["diagnostics"].is_array());
}

#[cfg(all(feature = "live", unix))]
#[test]
fn interfaces_command_succeeds_end_to_end_on_supported_unix_profiles() {
    let output = binary()
        .args(["--output", "json", "interfaces"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "packetcraftr.output/v1");
    assert_eq!(value["command"], "interfaces");
    assert_eq!(value["status"], "success");
    assert!(value["result"]["interfaces"].is_array());
}

#[cfg(not(feature = "native-route"))]
#[test]
fn unavailable_live_command_uses_capability_exit_code_and_json_error() {
    let output = binary()
        .args([
            "--output",
            "json",
            "send",
            "--packet",
            "ipv4(dst=127.0.0.1)/udp(dport=9)",
            "--link-mode",
            "layer3",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(4));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "error");
    assert_eq!(value["mode"], "aggregate");
    assert_eq!(value["error"]["kind"], "capability");
    assert_eq!(value["command"], "send");
}

#[test]
fn send_policy_denial_precedes_route_or_live_io() {
    let output = binary()
        .args([
            "--output",
            "json",
            "send",
            "--packet",
            "ipv4(dst=8.8.8.8)/udp(dport=9)",
            "--link-mode",
            "layer3",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["command"], "send");
    assert_eq!(value["error"]["code"], "policy.public_destination");
}

#[test]
fn scan_policy_and_request_errors_precede_resolver_route_and_live_io() {
    let hostname = binary()
        .args([
            "--output",
            "json",
            "scan",
            "lab.example",
            "--ports",
            "443",
            "--interface",
            "definitely-not-a-real-interface",
        ])
        .output()
        .unwrap();
    assert_eq!(hostname.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&hostname.stdout).unwrap();
    assert_eq!(value["command"], "scan");
    assert_eq!(value["error"]["code"], "policy.hostname_resolution");

    let public = binary()
        .args([
            "--output",
            "ndjson",
            "scan",
            "8.8.8.8",
            "--transport",
            "udp",
            "--ports",
            "53",
        ])
        .output()
        .unwrap();
    assert_eq!(public.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&public.stdout).unwrap();
    assert_eq!(value["sequence"], 0);
    assert_eq!(value["error"]["code"], "policy.public_destination");

    let invalid = binary()
        .args([
            "--output",
            "json",
            "scan",
            "192.168.56.10",
            "--transport",
            "icmp",
            "--ports",
            "80",
        ])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&invalid.stdout).unwrap();
    assert_eq!(value["error"]["code"], "cli.scan_limit");
}

#[test]
fn traceroute_policy_and_request_errors_precede_resolver_route_and_live_io() {
    let hostname = binary()
        .args([
            "--output",
            "json",
            "traceroute",
            "lab.example",
            "--interface",
            "definitely-not-a-real-interface",
        ])
        .output()
        .unwrap();
    assert_eq!(hostname.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&hostname.stdout).unwrap();
    assert_eq!(value["command"], "traceroute");
    assert_eq!(value["error"]["code"], "policy.hostname_resolution");

    let public = binary()
        .args(["--output", "ndjson", "traceroute", "8.8.8.8"])
        .output()
        .unwrap();
    assert_eq!(public.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&public.stdout).unwrap();
    assert_eq!(value["sequence"], 0);
    assert_eq!(value["error"]["code"], "policy.public_destination");

    let invalid = binary()
        .args([
            "--output",
            "json",
            "traceroute",
            "192.168.56.10",
            "--strategy",
            "icmp",
            "--port",
            "80",
        ])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&invalid.stdout).unwrap();
    assert_eq!(value["error"]["code"], "cli.traceroute_limit");
}

#[test]
fn dns_policy_and_request_errors_precede_resolver_route_and_live_io() {
    let hostname = binary()
        .args([
            "--output",
            "json",
            "dns",
            "resolver.example",
            "www.example.test",
            "--interface",
            "definitely-not-a-real-interface",
        ])
        .output()
        .unwrap();
    assert_eq!(hostname.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&hostname.stdout).unwrap();
    assert_eq!(value["command"], "dns");
    assert_eq!(value["error"]["code"], "policy.hostname_resolution");

    let public = binary()
        .args(["--output", "ndjson", "dns", "8.8.8.8", "www.example.test"])
        .output()
        .unwrap();
    assert_eq!(public.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&public.stdout).unwrap();
    assert_eq!(value["sequence"], 0);
    assert_eq!(value["error"]["code"], "policy.public_destination");

    let invalid = binary()
        .args([
            "--output",
            "json",
            "dns",
            "192.168.56.53",
            "bad name.example",
        ])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&invalid.stdout).unwrap();
    assert_eq!(value["error"]["code"], "packet.dns_query");
}

#[test]
fn fuzz_is_deterministic_offline_and_live_policy_precedes_route_io() {
    let arguments = [
        "--output",
        "json",
        "fuzz",
        "--packet",
        "raw(hex=\"00\")",
        "--seed",
        "9",
        "--cases",
        "3",
        "--strategy",
        "bit-flip",
        "--field",
        "0.bytes",
        "--interface",
        "definitely-not-a-real-interface",
    ];
    let first = binary().args(arguments).output().unwrap();
    let second = binary().args(arguments).output().unwrap();
    assert!(first.status.success());
    assert!(second.status.success());
    let first: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    let second: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(first["result"], second["result"]);
    assert_eq!(first["result"]["mode"], "offline");

    let public = binary()
        .args([
            "--output",
            "json",
            "fuzz",
            "--packet",
            "ipv4(src=192.0.2.1,dst=8.8.8.8)/udp(sport=40000,dport=9)/raw(hex=\"00\")",
            "--cases",
            "1",
            "--strategy",
            "bit-flip",
            "--field",
            "2.bytes",
            "--live",
            "--interface",
            "definitely-not-a-real-interface",
        ])
        .output()
        .unwrap();
    assert_eq!(public.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&public.stdout).unwrap();
    assert_eq!(value["error"]["code"], "policy.public_destination");
}

#[test]
fn fuzz_malformed_live_requires_both_explicit_opt_ins_before_route_io() {
    let base = [
        "--output",
        "json",
        "fuzz",
        "--packet",
        "ipv4(src=192.168.56.1,dst=192.168.56.2)/udp(sport=40000,dport=9)/raw(hex=\"00\")",
        "--cases",
        "1",
        "--strategy",
        "malformed",
        "--field",
        "1.length",
        "--mode",
        "permissive",
        "--live",
        "--interface",
        "definitely-not-a-real-interface",
    ];
    let call_site = binary()
        .args(base)
        .arg("--allow-permissive-packets")
        .output()
        .unwrap();
    assert_eq!(call_site.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&call_site.stdout).unwrap();
    assert_eq!(value["error"]["code"], "policy.fuzz_malformed_opt_in");

    let policy = binary()
        .args(base)
        .arg("--allow-malformed-live")
        .output()
        .unwrap();
    assert_eq!(policy.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&policy.stdout).unwrap();
    assert_eq!(value["error"]["code"], "policy.permissive_packet");
}

#[test]
fn fuzz_text_escapes_control_values_while_json_keeps_them_structured() {
    let common = [
        "fuzz",
        "--packet",
        "bsd_null(family=2,byte_order=\"little\")/ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=1,dport=2)",
        "--seed",
        "0",
        "--cases",
        "1",
        "--strategy",
        "boundary",
        "--field",
        "0.byte_order",
    ];
    let text = binary().args(common).output().unwrap();
    assert!(text.status.success());
    assert!(!text.stdout.contains(&0x1b));
    assert!(String::from_utf8(text.stdout).unwrap().contains("\\u001b"));

    let json = binary()
        .args(["--output", "json"])
        .args(common)
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(
        value["result"]["cases"][0]["mutation"]["value"]["value"],
        "\u{1b}[31mcontrol\u{1b}[0m"
    );
}

#[test]
fn send_budget_and_output_contracts_precede_route_or_live_io() {
    let budget = binary()
        .args([
            "--output",
            "json",
            "send",
            "--packet",
            "ipv4(dst=127.0.0.1)/udp(dport=9)",
            "--link-mode",
            "layer3",
            "--max-packets",
            "0",
        ])
        .output()
        .unwrap();
    assert_eq!(budget.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&budget.stdout).unwrap();
    assert_eq!(value["error"]["code"], "policy.packet_limit");

    let format = binary()
        .args([
            "--output",
            "ndjson",
            "send",
            "--packet",
            "ipv4(dst=8.8.8.8)/udp(dport=9)",
        ])
        .output()
        .unwrap();
    assert_eq!(format.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&format.stdout).unwrap();
    assert_eq!(value["sequence"], 0);
    assert_eq!(value["error"]["code"], "cli.output_format");
}

#[test]
fn invalid_capture_and_exchange_limits_precede_packet_policy() {
    let capture = binary()
        .args([
            "--output",
            "ndjson",
            "capture",
            "--packet",
            "ipv4(dst=8.8.8.8)/udp(dport=9)",
            "--max-queue-frames",
            "0",
        ])
        .output()
        .unwrap();
    assert_eq!(capture.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&capture.stdout).unwrap();
    assert_eq!(value["sequence"], 0);
    assert_eq!(value["error"]["code"], "cli.capture_limit");

    let exchange = binary()
        .args([
            "--output",
            "json",
            "exchange",
            "--packet",
            "ipv4(dst=8.8.8.8)/udp(dport=9)",
            "--timeout-ms",
            "3600001",
        ])
        .output()
        .unwrap();
    assert_eq!(exchange.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&exchange.stdout).unwrap();
    assert_eq!(value["error"]["code"], "cli.exchange_limit");
}

#[cfg(feature = "native-route")]
#[test]
fn native_plan_and_routes_are_passive_typed_workflows() {
    let plan = binary()
        .args([
            "--output",
            "json",
            "plan",
            "--packet",
            "ipv4(dst=127.0.0.1)/udp(dport=9)",
            "--link-mode",
            "layer3",
        ])
        .output()
        .unwrap();
    assert!(
        plan.status.success(),
        "{}",
        String::from_utf8_lossy(&plan.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&plan.stdout).unwrap();
    assert_eq!(plan["result"]["route"]["mode"], "layer3");
    assert!(
        plan["result"]["route"]["route"]["mtu"]
            .as_u64()
            .is_some_and(|mtu| mtu > 0)
    );

    let routes = binary()
        .args(["--output", "json", "routes"])
        .output()
        .unwrap();
    assert!(
        routes.status.success(),
        "{}",
        String::from_utf8_lossy(&routes.stderr)
    );
    let routes: serde_json::Value = serde_json::from_slice(&routes.stdout).unwrap();
    assert!(!routes["result"]["routes"].as_array().unwrap().is_empty());
}

#[test]
fn capture_commands_reserve_the_documented_queue_limit_contract() {
    for command in ["capture", "exchange"] {
        let output = binary().args([command, "--help"]).output().unwrap();
        assert!(output.status.success(), "{command}");
        let help = String::from_utf8(output.stdout).unwrap();
        for expected in [
            "--max-queue-frames",
            "--max-captured-bytes",
            "--snap-length",
            "--overflow-policy",
            "drop-newest",
            "drop-oldest",
            "[default: 4096]",
        ] {
            assert!(
                help.contains(expected),
                "{command}: missing {expected}\n{help}"
            );
        }
    }
}

#[test]
fn read_exposes_bounded_capture_file_writers() {
    let path = write_capture(&[b"one", b"two"], false);
    let output = binary()
        .args([
            "--output",
            "pcapng",
            "read",
            path.to_str().unwrap(),
            "--max-frames",
            "2",
        ])
        .output()
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut reader = Reader::new(std::io::Cursor::new(output.stdout)).unwrap();
    assert_eq!(reader.format(), CaptureFormat::PcapNg);
    assert_eq!(reader.next_frame().unwrap().unwrap().bytes.as_ref(), b"one");
    assert_eq!(reader.next_frame().unwrap().unwrap().bytes.as_ref(), b"two");
    assert!(reader.next_frame().unwrap().is_none());
}

#[test]
fn empty_replay_is_a_typed_aggregate_without_live_side_effects() {
    let path = write_capture(&[], false);
    let output = binary()
        .args([
            "--output",
            "json",
            "replay",
            path.to_str().unwrap(),
            "--interface",
            "definitely-missing-interface",
            "--timing",
            "immediate",
        ])
        .output()
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["command"], "replay");
    assert_eq!(value["result"]["frames_attempted"], 0);
    assert_eq!(value["result"]["frames_completed"], 0);
    assert_eq!(value["result"]["bytes_completed"], 0);
    assert_eq!(
        value["result"]["requested_interface"]["name"],
        "definitely-missing-interface"
    );
    assert_eq!(value["result"]["frames"], serde_json::json!([]));
}

#[test]
fn replay_rejects_unsupported_roots_and_public_targets_before_interface_io() {
    let unsupported = write_link_capture(LinkType::NULL, &[b"null"]);
    let output = binary()
        .args([
            "--output",
            "json",
            "replay",
            unsupported.to_str().unwrap(),
            "--interface",
            "definitely-missing-interface",
            "--timing",
            "immediate",
        ])
        .output()
        .unwrap();
    std::fs::remove_file(&unsupported).unwrap();
    assert_eq!(output.status.code(), Some(4));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "capability.replay_link_type");

    let public = write_public_raw_capture();
    let output = binary()
        .args([
            "--output",
            "json",
            "replay",
            public.to_str().unwrap(),
            "--interface",
            "definitely-missing-interface",
            "--timing",
            "immediate",
        ])
        .output()
        .unwrap();
    std::fs::remove_file(&public).unwrap();
    assert_eq!(output.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "policy.public_destination");
}

#[cfg(all(windows, feature = "live", not(feature = "native-route")))]
#[test]
fn default_windows_interfaces_uses_ip_helper() {
    let output = binary()
        .args(["--output", "json", "interfaces"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "success");
    assert_eq!(value["command"], "interfaces");
    let interfaces = value["result"]["interfaces"].as_array().unwrap();
    assert!(!interfaces.is_empty());
    assert!(interfaces.iter().all(|interface| {
        interface["index"].as_u64().is_some_and(|index| index != 0)
            && interface["mtu"].as_u64().is_some_and(|mtu| mtu != 0)
    }));
}

#[cfg(all(windows, feature = "native-route"))]
#[test]
fn native_windows_interfaces_uses_ip_helper() {
    let output = binary()
        .args(["--output", "json", "interfaces"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "success");
    assert_eq!(value["command"], "interfaces");
    let interfaces = value["result"]["interfaces"].as_array().unwrap();
    assert!(!interfaces.is_empty());
    assert!(interfaces.iter().all(|interface| {
        interface["index"].as_u64().is_some_and(|index| index != 0)
            && interface["mtu"].as_u64().is_some_and(|mtu| mtu != 0)
    }));
}

#[test]
fn conflicting_recipe_sources_use_cli_exit_code() {
    let output = binary()
        .args(["build", "--packet", "raw()", "--packet-file", "packet.json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn overflowing_numeric_interface_selectors_are_cli_errors_before_platform_io() {
    for arguments in [
        vec![
            "--output",
            "json",
            "plan",
            "--packet",
            "raw()",
            "--interface",
            "4294967296",
        ],
        vec![
            "--output",
            "json",
            "replay",
            "definitely-missing.pcap",
            "--interface",
            "4294967296",
        ],
    ] {
        let output = binary().args(arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stderr.is_empty());
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["error"]["kind"], "cli");
        assert!(
            value["error"]["message"]
                .as_str()
                .unwrap()
                .contains("interface index")
        );
    }
}

#[test]
fn piped_stdin_cannot_be_silently_ignored_by_an_explicit_recipe() {
    let mut child = binary()
        .args(["--output", "json", "build", "--packet", "raw(hex=00)"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"raw(hex=ff)")
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "error");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("exactly one")
    );
}

#[test]
fn cli_parse_errors_requested_as_ndjson_are_sequence_zero_records() {
    let output = binary()
        .args(["--output", "ndjson", "build", "--unknown-option"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["command"], "build");
    assert_eq!(value["mode"], "stream");
    assert_eq!(value["sequence"], 0);
    assert_eq!(value["status"], "error");
    assert_eq!(value["error"]["kind"], "cli");
}

#[cfg(unix)]
#[test]
fn non_utf8_arguments_do_not_panic_the_structured_parse_error_path() {
    use std::os::unix::ffi::OsStringExt;

    let invalid = std::ffi::OsString::from_vec(b"bad\xff".to_vec());
    let output = binary()
        .args(["--output", "json", "build", "--unknown-option"])
        .arg(invalid)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["command"], "build");
    assert_eq!(value["status"], "error");
    assert_eq!(value["error"]["kind"], "cli");
}

#[test]
fn read_ndjson_success_records_have_frozen_sequences() {
    let path = write_capture(&[&[0, 1], &[2, 3, 4]], false);
    let output = binary()
        .args(["--output", "ndjson", "read"])
        .arg(&path)
        .output()
        .unwrap();
    std::fs::remove_file(path).unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let records = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 2);
    for (sequence, record) in records.iter().enumerate() {
        assert_eq!(record["command"], "read");
        assert_eq!(record["mode"], "stream");
        assert_eq!(record["sequence"], sequence as u64);
        assert_eq!(record["status"], "success");
    }
    assert_eq!(records[0]["result"]["frame"]["bytes_hex"], "0001");
    assert_eq!(records[1]["result"]["frame"]["bytes_hex"], "020304");
}

#[test]
fn read_ndjson_terminal_errors_use_the_next_unused_sequence() {
    let path = write_capture(&[&[0xaa]], true);
    let output = binary()
        .args(["--output", "ndjson", "read"])
        .arg(&path)
        .output()
        .unwrap();
    std::fs::remove_file(path).unwrap();

    assert_eq!(output.status.code(), Some(3));
    let records = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["status"], "success");
    assert_eq!(records[0]["sequence"], 0);
    assert_eq!(records[1]["status"], "error");
    assert_eq!(records[1]["sequence"], 1);
    assert_eq!(records[1]["error"]["kind"], "packet");
}

#[test]
fn unsupported_json_for_read_is_typed_before_opening_the_input() {
    let output = binary()
        .args(["--output", "json", "read", "definitely-missing.pcap"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["mode"], "aggregate");
    assert_eq!(value["error"]["code"], "cli.output_format");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("text, ndjson, hex")
    );
}

#[cfg(unix)]
#[test]
fn closed_stdout_is_cleanly_classified_for_every_output_family() {
    let bytes = vec![0u8; 1024 * 1024];
    let raw_path = temp_path("closed-stdout-raw");
    std::fs::write(&raw_path, &bytes).unwrap();
    let capture_path = write_link_capture(LinkType(147), &[&bytes]);

    for format in ["json", "hex", "raw"] {
        let mut child = binary()
            .args(["--output", format, "dissect", "--file"])
            .arg(&raw_path)
            .args(["--link-type", "147"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        drop(child.stdout.take());
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(5), "{format}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("write stdout failed"), "{format}: {stderr}");
        assert!(!stderr.contains("panicked"), "{format}: {stderr}");
    }

    for format in ["text", "ndjson", "pcap", "pcapng"] {
        let mut child = binary()
            .args(["--output", format, "read"])
            .arg(&capture_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        drop(child.stdout.take());
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(5), "{format}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("write stdout failed")
                || stderr.contains("write capture output failed")
                || stderr.contains("capture I/O failed"),
            "{format}: {stderr}"
        );
        assert!(!stderr.contains("panicked"), "{format}: {stderr}");
    }

    std::fs::remove_file(raw_path).unwrap();
    std::fs::remove_file(capture_path).unwrap();
}

#[test]
fn text_errors_escape_terminal_controls_while_json_stays_structured() {
    let path = "missing-\u{1b}[31m-\n-packet.bin";
    let text = binary().args(["dissect", "--file", path]).output().unwrap();
    assert_eq!(text.status.code(), Some(2));
    assert!(!text.stderr.contains(&0x1b));
    let rendered = String::from_utf8(text.stderr).unwrap();
    assert!(rendered.contains("\\u{1b}"), "{rendered:?}");
    assert!(rendered.contains("\\n"), "{rendered:?}");

    let machine = binary()
        .args(["--output", "json", "dissect", "--file", path])
        .output()
        .unwrap();
    assert_eq!(machine.status.code(), Some(2));
    assert!(!machine.stdout.contains(&0x1b));
    let value: serde_json::Value = serde_json::from_slice(&machine.stdout).unwrap();
    let message = value["error"]["message"].as_str().unwrap();
    assert!(message.contains('\u{1b}'));
    assert!(message.contains('\n'));
    assert_eq!(value["error"]["kind"], "cli");
}
