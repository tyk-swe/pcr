// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::UNIX_EPOCH;

use packetcraftr::capture::{Format as CaptureFormat, Frame, LinkType, Writer};

use super::support::{binary, decode_output_hex, temp_path, write_capture};

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
fn packet_document_build_dissect_capture_read_pipeline_is_exact() {
    let document = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/documents/packet-ipv4-udp.json");
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
fn protocols_text_lists_manifest_order_and_describes_ordered_fields() {
    let list = binary().arg("protocols").output().unwrap();
    assert!(list.status.success());
    assert!(list.stderr.is_empty());
    let lines = std::str::from_utf8(&list.stdout)
        .unwrap()
        .lines()
        .collect::<Vec<_>>();
    assert_eq!(
        lines.len(),
        packetcraftr::protocol::support::BUILTIN_PROTOCOLS.len()
    );
    assert!(lines[0].starts_with("arp aliases=[] build=true"));
    assert!(lines[4].starts_with("geneve aliases=[] build=true"));
    assert!(lines[9].starts_with("ipv4 aliases=[ip, ip4] build=true"));
    assert!(lines[18].starts_with("mpls aliases=[] build=true"));
    assert!(lines[21].starts_with("raw_ip aliases=[rawip] build=false"));
    assert!(lines[26].starts_with("vlan8021ad aliases=[dot1ad, 8021ad, qinq]"));

    let detail = binary().args(["protocols", "IP4"]).output().unwrap();
    assert!(detail.status.success());
    assert!(detail.stderr.is_empty());
    let detail = String::from_utf8(detail.stdout).unwrap();
    assert!(detail.starts_with("protocol: ipv4\naliases: [ip, ip4]\n"));
    assert!(detail.contains("\nfields:\n  dscp_ecn kind=unsigned"));
    assert!(
        detail.find("dscp_ecn").unwrap() < detail.find("total_length").unwrap(),
        "{detail}"
    );
    assert!(detail.contains("  options kind=bytes"));
}

#[test]
fn protocols_json_lists_describes_aliases_and_classifies_unknown_names() {
    let list = binary()
        .args(["--output", "json", "protocols"])
        .output()
        .unwrap();
    assert!(list.status.success());
    assert!(list.stderr.is_empty());
    let list: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(list["command"], "protocols");
    assert_eq!(
        list["result"]["protocols"].as_array().unwrap().len(),
        packetcraftr::protocol::support::BUILTIN_PROTOCOLS.len()
    );
    assert!(list["result"]["protocols"][0].get("fields").is_none());

    let detail = binary()
        .args(["--output", "json", "protocols", "IP4"])
        .output()
        .unwrap();
    assert!(detail.status.success());
    let detail: serde_json::Value = serde_json::from_slice(&detail.stdout).unwrap();
    assert_eq!(detail["result"]["protocol"]["protocol"], "ipv4");
    assert_eq!(
        detail["result"]["protocol"]["fields"][0]["name"],
        "dscp_ecn"
    );

    let raw_ip = binary()
        .args(["--output", "json", "protocols", "RAWIP"])
        .output()
        .unwrap();
    assert!(raw_ip.status.success());
    let raw_ip: serde_json::Value = serde_json::from_slice(&raw_ip.stdout).unwrap();
    assert_eq!(raw_ip["result"]["protocol"]["protocol"], "raw_ip");
    assert_eq!(
        raw_ip["result"]["protocol"]["fields"],
        serde_json::json!([])
    );

    let unknown = binary()
        .args(["--output", "json", "protocols", "unknown"])
        .output()
        .unwrap();
    assert_eq!(unknown.status.code(), Some(2));
    assert!(unknown.stderr.is_empty());
    let unknown: serde_json::Value = serde_json::from_slice(&unknown.stdout).unwrap();
    assert_eq!(unknown["command"], "protocols");
    assert_eq!(unknown["error"]["code"], "cli.protocol");
    assert_eq!(
        unknown["error"]["remediation"],
        "run `packetcraftr protocols` to list built-in protocols"
    );
}

#[test]
fn protocols_rejects_non_aggregate_formats_before_name_resolution() {
    for format in ["ndjson", "hex", "raw", "pcap", "pcapng"] {
        let output = binary()
            .args(["--output", format, "protocols", "unknown"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{format}");
        let structured = matches!(format, "ndjson");
        if structured {
            let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(value["command"], "protocols");
            assert_eq!(value["error"]["code"], "cli.output_format");
        } else {
            assert!(output.stdout.is_empty(), "{format}");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("protocols does not support"),
                "{format}"
            );
        }
    }
}

/// Builds one exact frame with the CLI, so fixtures never carry hand-computed
/// checksums that could drift from what the dissector expects.
fn built_frame(expression: &str) -> Vec<u8> {
    let output = binary()
        .args(["--output", "raw", "build", "--packet", expression])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// Two Ethernet frames that differ in transport, address, and TCP flags, so a
/// filter has something to discriminate on.
fn filterable_capture() -> PathBuf {
    let udp = built_frame(
        "ethernet(source=02:00:00:00:00:01,destination=02:00:00:00:00:02)\
         /ipv4(source=10.0.0.1,destination=10.0.0.2)\
         /udp(source_port=1000,destination_port=53)/raw(text=q)",
    );
    let tcp = built_frame(
        "ethernet(source=02:00:00:00:00:03,destination=02:00:00:00:00:04)\
         /ipv4(source=192.168.0.1,destination=192.168.0.2)\
         /tcp(source_port=1000,destination_port=443,flags=2)",
    );
    write_capture(&[&udp, &tcp], false)
}

#[test]
fn read_filters_frames_and_can_include_the_dissected_stack() {
    let capture = filterable_capture();
    let read = |arguments: &[&str]| -> String {
        let mut command = binary();
        command.arg("read").arg(&capture).args(arguments);
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    };

    // Without a filter both frames are emitted, exactly as before.
    assert_eq!(read(&[]).lines().count(), 2);

    // Layer presence, conventional spellings, and prefix membership all select
    // one of the two frames.
    assert_eq!(read(&["--filter", "udp"]).lines().count(), 1);
    assert_eq!(read(&["--filter", "tcp"]).lines().count(), 1);
    assert_eq!(read(&["--filter", "ip.src == 10.0.0.1"]).lines().count(), 1);
    assert_eq!(
        read(&["--filter", "ip.src in 192.168.0.0/16"])
            .lines()
            .count(),
        1
    );
    assert_eq!(read(&["--filter", "tcp.flags.syn == 1"]).lines().count(), 1);
    assert_eq!(read(&["--filter", "udp || tcp"]).lines().count(), 2);

    // Negation covers the whole test, so `!tcp.flags.ack` is also true of a
    // frame that carries no TCP at all. Pairing it with a presence test is
    // what narrows it to unacknowledged TCP.
    assert_eq!(read(&["--filter", "!tcp.flags.ack"]).lines().count(), 2);
    assert_eq!(
        read(&["--filter", "tcp && !tcp.flags.ack"]).lines().count(),
        1
    );
    // A filter that matches nothing succeeds and emits nothing.
    assert_eq!(
        read(&["--filter", "ip.src == 203.0.113.9"]).lines().count(),
        0
    );

    // `--dissect` adds the layer stack; plain reads stay free of it.
    let plain = read(&["--output", "ndjson"]);
    assert!(!plain.contains("\"decoded\""));
    let dissected = read(&["--output", "ndjson", "--dissect"]);
    assert!(dissected.contains("\"decoded\""));
    assert!(dissected.contains("\"ethernet\""));

    // Text output names the layer chain, so the flag is not NDJSON-only.
    assert!(!read(&[]).contains("layers="));
    let text = read(&["--dissect"]);
    assert!(text.contains("layers=ethernet/ipv4/udp"), "{text}");
    assert!(text.contains("layers=ethernet/ipv4/tcp"), "{text}");

    // Emitted record sequences stay contiguous even when frames are filtered
    // out, so a stream never appears to have lost records.
    let second_only = read(&["--output", "ndjson", "--filter", "tcp"]);
    assert_eq!(second_only.lines().count(), 1);
    assert!(second_only.contains("\"sequence\":0"));
}

#[test]
fn read_filtering_to_a_capture_file_extracts_a_subset() {
    let capture = filterable_capture();
    let output = binary()
        .args(["--output", "pcap", "read"])
        .arg(&capture)
        .args(["--filter", "udp"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let subset = temp_path("filtered-subset");
    std::fs::write(&subset, &output.stdout).unwrap();

    // The extracted capture holds only the matching frame and reads back.
    let reread = binary().arg("read").arg(&subset).output().unwrap();
    assert!(reread.status.success());
    assert_eq!(String::from_utf8(reread.stdout).unwrap().lines().count(), 1);
}

#[test]
fn filtering_to_a_capture_file_with_no_matches_writes_an_empty_capture() {
    let capture = filterable_capture();
    for format in ["pcap", "pcapng"] {
        // Matching nothing is a legitimate result, so the extraction has to
        // produce a readable capture rather than failing.
        let output = binary()
            .args(["--output", format, "read"])
            .arg(&capture)
            .args(["--filter", "ip.src == 203.0.113.9"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{format}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty(), "{format} needs its headers");

        let subset = temp_path(&format!("empty-subset-{format}"));
        std::fs::write(&subset, &output.stdout).unwrap();
        let reread = binary().arg("read").arg(&subset).output().unwrap();
        assert!(
            reread.status.success(),
            "{format}: {}",
            String::from_utf8_lossy(&reread.stderr)
        );
        assert!(reread.stdout.is_empty(), "{format} holds no frames");
        std::fs::remove_file(subset).unwrap();
    }
}

#[test]
fn filtering_a_multi_interface_capture_preserves_every_link_type() {
    let capture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/captures/pcapng/multi-link.pcapng");

    // PCAPNG keeps a link type per interface, so a filtered extraction must
    // carry each surviving frame's own medium through unchanged.
    let output = binary()
        .args(["--output", "pcapng", "read"])
        .arg(&capture)
        .args(["--filter", "ipv4 || ipv6 || raw"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let subset = temp_path("multi-link-subset");
    std::fs::write(&subset, &output.stdout).unwrap();
    let reread = binary()
        .args(["--output", "ndjson", "read"])
        .arg(&subset)
        .output()
        .unwrap();
    assert!(reread.status.success());
    let link_types: Vec<u64> = String::from_utf8(reread.stdout)
        .unwrap()
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).unwrap()["result"]["frame"]["link_type"]
                .as_u64()
                .unwrap()
        })
        .collect();
    assert_eq!(link_types, vec![1, 101]);
    std::fs::remove_file(subset).unwrap();

    // Classic PCAP cannot hold that, and refuses it exactly as an unfiltered
    // read does, rather than emitting a header and failing partway.
    let unfiltered = binary()
        .args(["--output", "pcap", "read"])
        .arg(&capture)
        .output()
        .unwrap();
    let filtered = binary()
        .args(["--output", "pcap", "read"])
        .arg(&capture)
        .args(["--filter", "ipv4"])
        .output()
        .unwrap();
    assert_eq!(filtered.status.code(), unfiltered.status.code());
    assert!(filtered.stdout.is_empty(), "no partial capture is emitted");
    assert!(
        String::from_utf8_lossy(&filtered.stderr).contains("pcapng interface metadata"),
        "{}",
        String::from_utf8_lossy(&filtered.stderr)
    );
}

#[test]
fn filtered_capture_output_honours_raised_limits() {
    let capture = filterable_capture();
    // A raised per-frame bound must reach the writer too, not just the reader.
    let output = binary()
        .args(["--output", "pcapng", "read"])
        .arg(&capture)
        .args(["--filter", "udp", "--max-frame-bytes", "33554432"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.stdout.is_empty());
}

#[test]
fn read_rejects_dissection_where_no_format_can_show_it() {
    let capture = filterable_capture();
    for format in ["hex", "pcap", "pcapng"] {
        let output = binary()
            .args(["--output", format, "read"])
            .arg(&capture)
            .arg("--dissect")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{format}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("--dissect"),
            "{format}"
        );
    }
}

#[test]
fn read_rejects_a_filter_it_cannot_evaluate() {
    let capture = filterable_capture();
    // An unknown field is a command-line error, not a silent empty result.
    let unknown = binary()
        .arg("read")
        .arg(&capture)
        .args(["--filter", "nope.missing == 1"])
        .output()
        .unwrap();
    assert_eq!(unknown.status.code(), Some(2));
    assert!(unknown.stdout.is_empty());

    // So is a filter needing a conversation index this command never assigns.
    let stream = binary()
        .arg("read")
        .arg(&capture)
        .args(["--filter", "tcp.stream == 0"])
        .output()
        .unwrap();
    assert_eq!(stream.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&stream.stderr).contains("conversation index"),
        "{}",
        String::from_utf8_lossy(&stream.stderr)
    );
}

#[test]
fn dissect_filter_selects_emission_without_changing_the_match_output() {
    let frame = built_frame(
        "ipv4(source=192.0.2.1,destination=198.51.100.2)\
         /udp(source_port=12345,destination_port=9)/raw(text=hi)",
    );
    let hex = frame
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let dissect = |arguments: &[&str]| {
        let mut command = binary();
        command
            .args(["--output", "json", "dissect", "--link-type", "101"])
            .args(["--hex", &hex])
            .args(arguments);
        command.output().unwrap()
    };

    // A matching filter emits exactly what an unfiltered dissect emits.
    let unfiltered = dissect(&[]);
    let matched = dissect(&["--filter", "udp.dstport == 9 && ip.src == 192.0.2.1"]);
    assert!(
        matched.status.success(),
        "{}",
        String::from_utf8_lossy(&matched.stderr)
    );
    assert_eq!(matched.stdout, unfiltered.stdout);
    let value: serde_json::Value = serde_json::from_slice(&matched.stdout).unwrap();
    assert_eq!(value["status"], "success");
    assert_eq!(value["result"]["packet"]["layers"][0]["protocol"], "ipv4");

    // A frame the filter rejects emits nothing, and the command succeeds.
    for format in ["json", "text", "hex", "raw"] {
        let mut command = binary();
        command
            .args(["--output", format, "dissect", "--link-type", "101"])
            .args(["--hex", &hex])
            .args(["--filter", "udp.dstport == 10"]);
        let unmatched = command.output().unwrap();
        assert!(
            unmatched.status.success(),
            "{format}: {}",
            String::from_utf8_lossy(&unmatched.stderr)
        );
        assert!(unmatched.stdout.is_empty(), "{format}");
        assert!(unmatched.stderr.is_empty(), "{format}");
    }

    // An unsupported output format is refused whether or not the frame
    // matches, so filtering never hides a contract error.
    let unsupported = binary()
        .args(["--output", "pcap", "dissect", "--link-type", "101"])
        .args(["--hex", &hex])
        .args(["--filter", "udp.dstport == 10"])
        .output()
        .unwrap();
    assert_eq!(unsupported.status.code(), Some(2));
}

#[test]
fn dissect_rejects_a_filter_it_cannot_evaluate() {
    // The unknown field is refused before any frame bytes are read, and a
    // conversation-index filter is refused because dissect never assigns one.
    for (filter, needle) in [
        ("nope.missing == 1", "nope.missing"),
        ("tcp.stream == 0", "conversation index"),
    ] {
        let output = binary()
            .args(["dissect", "--hex", "45", "--filter", filter])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{filter}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(needle),
            "{filter}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn stats_reports_conversations_protocols_and_io_over_a_capture() {
    let capture = filterable_capture();
    let stats = |arguments: &[&str]| -> String {
        let mut command = binary();
        command.arg("stats").arg(&capture).args(arguments);
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    };

    let conversations = stats(&["--table", "conversations"]);
    assert!(conversations.starts_with("matched 2 of 2 frame(s)"));
    assert!(conversations.contains("udp stream 0: 10.0.0.1:1000 <-> 10.0.0.2:53"));
    assert!(conversations.contains("tcp stream 0: 192.168.0.1:1000 <-> 192.168.0.2:443"));

    let protocols = stats(&["--table", "protocols"]);
    assert!(protocols.contains("ethernet: frames 2 (100.0%)"));
    assert!(protocols.contains("udp: frames 1 (50.0%)"));

    // Filtering narrows the tables while frame numbering stays capture-global.
    let filtered = stats(&["--table", "endpoints", "--filter", "tcp"]);
    assert!(filtered.starts_with("matched 1 of 2 frame(s)"));
    assert!(filtered.contains("192.168.0.1: tx 1 frame(s)"));
    assert!(!filtered.contains("10.0.0.1"));

    // Stream-aware filters are supported here, unlike frame-at-a-time
    // commands, because stats assigns conversation indices.
    let stream = stats(&["--table", "conversations", "--filter", "udp.stream == 0"]);
    assert!(stream.contains("udp stream 0"));
    assert!(!stream.contains("tcp stream"));

    let io = stats(&["--table", "io", "--interval-ms", "500"]);
    assert!(io.contains("+0ns: frames 1"));
}

#[test]
fn stats_rejects_unsupported_formats_and_invalid_limits_up_front() {
    let unsupported = binary()
        .args(["--output", "hex", "stats", "missing.pcap"])
        .output()
        .unwrap();
    assert_eq!(unsupported.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&unsupported.stderr).contains("does not support hex"),
        "{}",
        String::from_utf8_lossy(&unsupported.stderr)
    );

    let interval = binary()
        .args(["stats", "missing.pcap", "--interval-ms", "0"])
        .output()
        .unwrap();
    assert_eq!(interval.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&interval.stderr).contains("interval"),
        "{}",
        String::from_utf8_lossy(&interval.stderr)
    );
}

#[test]
fn stats_rejects_invalid_analysis_limits_before_opening_the_capture() {
    // The file does not exist; the limit error must still win.
    let output = binary()
        .args(["stats", "definitely-missing.pcap", "--max-flows", "0"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("max_flows"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// One TCP conversation exhibiting a retransmission, a duplicate
/// acknowledgment, and a reset, so `expert` has anomalies to report.
fn anomalous_capture() -> PathBuf {
    let data = built_frame(
        "ethernet/ipv4(source=10.0.0.1,destination=10.0.0.2)\
         /tcp(source_port=1000,destination_port=443,sequence=100,acknowledgment=0,\
         flags=16,window=512)/raw(text=data)",
    );
    let ack = built_frame(
        "ethernet/ipv4(source=10.0.0.2,destination=10.0.0.1)\
         /tcp(source_port=443,destination_port=1000,sequence=500,acknowledgment=100,\
         flags=16,window=512)",
    );
    let reset = built_frame(
        "ethernet/ipv4(source=10.0.0.2,destination=10.0.0.1)\
         /tcp(source_port=443,destination_port=1000,sequence=501,acknowledgment=0,\
         flags=4,window=0)",
    );
    write_capture(&[&data, &data, &ack, &ack, &reset], false)
}

#[test]
fn expert_reports_tcp_anomalies_over_a_capture() {
    let capture = anomalous_capture();
    let expert = |arguments: &[&str]| -> String {
        let mut command = binary();
        command.arg("expert").arg(&capture).args(arguments);
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    };

    let text = expert(&[]);
    assert!(
        text.contains("#2 Warning tcp.retransmission (tcp stream 0)"),
        "{text}"
    );
    assert!(
        text.contains("#4 Warning tcp.duplicate_ack (tcp stream 0)"),
        "{text}"
    );
    assert!(
        text.contains("#5 Warning tcp.reset (tcp stream 0)"),
        "{text}"
    );
    assert!(
        text.contains(
            "found 3 finding(s) (0 error(s), 3 warning(s), 0 note(s)) in 5 of 5 frame(s)"
        ),
        "{text}"
    );

    // NDJSON emits one record per finding plus a terminal summary, with
    // contiguous sequence numbers.
    let stream = expert(&["--output", "ndjson"]);
    assert_eq!(stream.lines().count(), 4);
    assert!(stream.contains("\"sequence\":0"));
    assert!(stream.contains("\"sequence\":3"));
    assert!(stream.contains("\"frames_read\":5"));

    // Stream-aware filters are supported because expert assigns conversation
    // indices; frame numbering stays capture-global under a filter.
    let filtered = expert(&["--filter", "tcp.stream == 0"]);
    assert!(filtered.contains("#5 Warning tcp.reset"), "{filtered}");

    // A filter narrowing to the reset frame alone leaves no prior segments to
    // compare against, so only the reset itself is reported.
    let reset_only = expert(&["--filter", "tcp.flags.reset == 1"]);
    assert!(reset_only.contains("in 1 of 5 frame(s)"), "{reset_only}");
    assert!(!reset_only.contains("tcp.retransmission"), "{reset_only}");
}

#[test]
fn expert_rejects_unsupported_formats_and_invalid_limits_up_front() {
    let unsupported = binary()
        .args(["--output", "hex", "expert", "missing.pcap"])
        .output()
        .unwrap();
    assert_eq!(unsupported.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&unsupported.stderr).contains("does not support hex"),
        "{}",
        String::from_utf8_lossy(&unsupported.stderr)
    );

    // The file does not exist; the limit error must still win.
    let limits = binary()
        .args(["expert", "definitely-missing.pcap", "--max-flows", "0"])
        .output()
        .unwrap();
    assert_eq!(limits.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&limits.stderr).contains("max_flows"),
        "{}",
        String::from_utf8_lossy(&limits.stderr)
    );
}

/// A bidirectional conversation plus a decoy, so following proves both
/// direction attribution and conversation selection.
fn followable_capture() -> PathBuf {
    let ping = built_frame(
        "ethernet/ipv4(source=10.0.0.1,destination=10.0.0.2)\
         /tcp(source_port=1000,destination_port=443,sequence=100,acknowledgment=0,\
         flags=16,window=512)/raw(text=ping!)",
    );
    let pong = built_frame(
        "ethernet/ipv4(source=10.0.0.2,destination=10.0.0.1)\
         /tcp(source_port=443,destination_port=1000,sequence=500,acknowledgment=105,\
         flags=16,window=512)/raw(text=pong!)",
    );
    let decoy = built_frame(
        "ethernet/ipv4(source=10.0.0.9,destination=10.0.0.8)\
         /udp(source_port=53,destination_port=53)/raw(text=decoy)",
    );
    write_capture(&[&ping, &decoy, &pong], false)
}

#[test]
fn follow_extracts_a_conversation_in_every_format() {
    let capture = followable_capture();
    let follow = |arguments: &[&str]| -> Vec<u8> {
        let mut command = binary();
        command.arg("follow").arg(&capture).args(arguments);
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    };

    let text = String::from_utf8(follow(&["--stream", "tcp:0"])).unwrap();
    assert!(text.contains("> #1 ping!"), "{text}");
    assert!(text.contains("< #3 pong!"), "{text}");
    assert!(
        text.contains(
            "followed tcp stream 0: client 10.0.0.1:1000 sent 5 byte(s), \
             server 10.0.0.2:443 sent 5 byte(s), 0 byte(s) undelivered in 2 frame(s)"
        ),
        "{text}"
    );

    // Raw output is the exact reassembled bytes of one direction.
    assert_eq!(
        follow(&[
            "--stream",
            "tcp:0",
            "--direction",
            "client",
            "--output",
            "raw"
        ]),
        b"ping!"
    );
    assert_eq!(
        follow(&[
            "--stream",
            "tcp:0",
            "--direction",
            "server",
            "--output",
            "raw"
        ]),
        b"pong!"
    );

    let hex = String::from_utf8(follow(&["--stream", "tcp:0", "--output", "hex"])).unwrap();
    assert!(hex.contains("> #1 70696e6721"), "{hex}");

    // The UDP decoy is its own conversation under its own index.
    assert_eq!(
        follow(&[
            "--stream",
            "udp:0",
            "--direction",
            "client",
            "--output",
            "raw"
        ]),
        b"decoy"
    );

    // A conversation the capture does not hold follows to nothing.
    let empty = String::from_utf8(follow(&["--stream", "tcp:7"])).unwrap();
    assert_eq!(empty, "followed tcp stream 7: no frames\n");
}

#[test]
fn follow_rejects_bad_specs_and_ambiguous_raw_up_front() {
    for (arguments, needle) in [
        (
            vec!["follow", "missing.pcap", "--stream", "bogus"],
            "expected tcp:INDEX or udp:INDEX",
        ),
        (
            vec![
                "--output",
                "raw",
                "follow",
                "missing.pcap",
                "--stream",
                "tcp:0",
            ],
            "choose --direction client or --direction server",
        ),
    ] {
        let output = binary().args(&arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(needle),
            "{arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // A machine format's refusal is itself a machine record.
    let ndjson = binary()
        .args([
            "--output",
            "ndjson",
            "follow",
            "missing.pcap",
            "--stream",
            "tcp:0",
        ])
        .output()
        .unwrap();
    assert_eq!(ndjson.status.code(), Some(2));
    let record: serde_json::Value = serde_json::from_slice(&ndjson.stdout).unwrap();
    assert_eq!(record["error"]["code"], "cli.output_format");
}
