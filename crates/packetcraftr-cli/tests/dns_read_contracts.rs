// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::{assert_contiguous, parse_json, parse_ndjson, run, run_success};

use packetcraftr_core::capture_file::{Format, Writer};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::application::dns::Dns;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::network::Ipv6;
use packetcraftr_core::protocol::transport::Udp;
use packetcraftr_core::{build, codec};

#[test]
fn offline_dns_output_preserves_records_and_scoped_transaction_evidence() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/dns-response.pcap");
    let path = path.to_str().unwrap();
    let document = parse_json(&run_success(&["--output", "json", "dns-read", path]));
    let result = &document["result"];
    assert_eq!(result["summary"]["complete_messages"], 1);
    assert_eq!(result["transactions"][0]["status"], "orphan_response");
    assert_eq!(result["messages"][0]["sources"][0]["number"], 1);
    assert!(
        result["messages"][0]["fields"]["answers"]["value"]
            .as_array()
            .unwrap()
            .len()
            == 1
    );
    let records = parse_ndjson(&run_success(&["--output", "ndjson", "dns-read", path]));
    assert_eq!(
        records
            .iter()
            .map(|v| v["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["dns_message", "dns_transaction", "complete"]
    );
    let output = run(&[
        "--output",
        "ndjson",
        "dns-read",
        path,
        "--max-application-output-bytes",
        "1",
    ]);
    assert!(!output.status.success());
    let records = parse_ndjson(&output);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["event"], "error");
    assert_eq!(records[0]["sequence"], 0);
    let output = run(&["--output", "json", "dns-read", path, "--stream", "tcp:999"]);
    assert!(!output.status.success());
    let output = run(&["--output", "json", "dns-read", path, "--bad-option"]);
    let error = parse_json(&output);
    assert_eq!(error["command"], "dns-read");
}

#[test]
fn additional_dns_ports_keep_the_standard_port() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/dns-response.pcap");
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "dns-read",
        path.to_str().unwrap(),
        "--dns-port",
        "5353",
    ]));
    assert_eq!(document["result"]["summary"]["complete_messages"], 1);
}

#[test]
fn application_output_budget_counts_only_compact_event_payloads() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/dns-response.pcap");
    let expected_text = concat!(
        "DNS udp:0 message=1 status=complete 192.0.2.53:53 -> 198.51.100.8:49152 frames=1\n",
        "  dns question: example.test. type=1 class=1\n",
        "  dns answer: example.test. type=1 class=1 ttl=60 {address=192.0.2.8,kind=a}\n",
        "  dns authority: example.test. type=2 class=1 ttl=300 {kind=ns,name=ns.example.test.}\n",
        "  dns additional: example.test. type=65000 class=1 ttl=7 {kind=unknown,rdata=ff00c0ff,type=65000}\n",
        "  dns additional: . type=41 class=1232 ttl=16810048 {dnssec_ok=true,extended_response_code=1,flags=32832,kind=opt,options={code=12,data=00ff01},udp_payload_size=1232,version=0}\n",
        "  transaction id=4660 status=orphan_response queries=none response=1 latest_latency=none\n",
        "1 DNS messages; 0 matched and 0 unanswered transactions in 1 captured frames\n",
    );
    common::application_output::assert_exact_budget(
        "dns-read",
        &path,
        &[
            ("dns_message", "messages"),
            ("dns_transaction", "transactions"),
            ("dns_stream_issue", "issues"),
        ],
        expected_text,
        "application output exceeds --max-application-output-bytes",
        &[],
    );
}

#[test]
fn ndjson_budget_shares_the_charge_across_event_kinds() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/dns-response.pcap");
    let path = path.to_str().unwrap();
    let document = parse_json(&run_success(&["--output", "json", "dns-read", path]));
    let first = serde_json::to_vec(&document["result"]["messages"][0])
        .unwrap()
        .len()
        .to_string();
    let output = run(&[
        "--output",
        "ndjson",
        "dns-read",
        path,
        "--max-application-output-bytes",
        &first,
    ]);
    assert_eq!(output.status.code(), Some(6));
    let records = parse_ndjson(&output);
    assert_eq!(
        records
            .iter()
            .map(|record| record["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["dns_message", "error"]
    );
    assert_contiguous(&records);
    assert_eq!(records[0]["result"], document["result"]["messages"][0]);
    assert_eq!(records[1]["error"]["code"], "policy.denied");
    assert_eq!(
        records[1]["error"]["message"],
        "application output exceeds --max-application-output-bytes"
    );
}

#[test]
fn text_output_brackets_ipv6_endpoints() {
    let mut packet = Packet::new();
    packet.push(Ipv6 {
        source: "2001:db8::1".parse().unwrap(),
        destination: "2001:db8::2".parse().unwrap(),
        ..Ipv6::default()
    });
    packet.push(Udp {
        source_port: 53,
        destination_port: 49152,
        ..Udp::default()
    });
    packet.push(Dns::try_from(vec![0x12, 0x34, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap());
    let built = build::Builder::new(builtin::registry())
        .build(packet, codec::Context::default(), build::Options::default())
        .unwrap();
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut writer = Writer::new(file.reopen().unwrap(), Format::Pcap, LinkType::IPV6).unwrap();
    writer
        .write_frame(&Frame::new(std::time::UNIX_EPOCH, LinkType::IPV6, built.bytes).unwrap())
        .unwrap();
    writer.into_inner().sync_all().unwrap();
    let output = run_success(&["dns-read", file.path().to_str().unwrap()]);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains(" [2001:db8::1]:53 -> [2001:db8::2]:49152 frames=1\n"),
        "{text:?}"
    );
}

fn hostile_dns_capture() -> tempfile::NamedTempFile {
    let label: &[u8] = b"ev\x1b[31mil\xe2\x80\xae";
    let txt: &[u8] = b"x\x1b]0;owned\x07\x1b[2Jy";
    let mut dns = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    dns.push(u8::try_from(label.len()).unwrap());
    dns.extend_from_slice(label);
    dns.extend_from_slice(b"\x04test\x00");
    dns.extend_from_slice(&[0, 16, 0, 1]);
    dns.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60]);
    dns.extend_from_slice(&u16::try_from(txt.len() + 1).unwrap().to_be_bytes());
    dns.push(u8::try_from(txt.len()).unwrap());
    dns.extend_from_slice(txt);
    let udp_length = u16::try_from(8 + dns.len()).unwrap();
    let mut packet = vec![
        0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0, 192, 0, 2, 53, 198, 51, 100, 8,
    ];
    packet[2..4].copy_from_slice(&(20 + udp_length).to_be_bytes());
    let mut sum = packet
        .chunks(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum::<u32>();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!u16::try_from(sum).unwrap()).to_be_bytes());
    packet.extend_from_slice(&53_u16.to_be_bytes());
    packet.extend_from_slice(&49152_u16.to_be_bytes());
    packet.extend_from_slice(&udp_length.to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&dns);
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut writer = Writer::new(file.reopen().unwrap(), Format::Pcap, LinkType::IPV4).unwrap();
    writer
        .write_frame(&Frame::new(std::time::UNIX_EPOCH, LinkType::IPV4, packet).unwrap())
        .unwrap();
    writer.into_inner().sync_all().unwrap();
    file
}

#[test]
fn captured_dns_names_and_record_text_render_without_terminal_escapes() {
    let capture = hostile_dns_capture();
    let path = capture.path().to_str().unwrap();
    for arguments in [&["dns-read", path][..], &["read", path, "--dissect"]] {
        let output = run_success(arguments);
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            !text
                .chars()
                .any(|character| character.is_control() && character != '\n'),
            "{arguments:?}: {text:?}"
        );
        assert!(!text.contains('\u{202e}'), "{arguments:?}: {text:?}");
        assert!(text.contains("ev\\027[31mil"), "{arguments:?}: {text:?}");
        assert!(text.contains("dns answer:"), "{arguments:?}: {text:?}");
    }
    // The machine document keeps the exact name, in DNS presentation form,
    // and the raw label bytes in `wire_hex`.
    let document = parse_json(&run_success(&["--output", "json", "dns-read", path]));
    let message = &document["result"]["messages"][0];
    let name = "ev\\027[31mil\\226\\128\\174.test.";
    assert_eq!(
        message["fields"]["questions"]["value"][0]["value"]["name"]["value"],
        name
    );
    assert_eq!(
        message["fields"]["answers"]["value"][0]["value"]["owner"]["value"],
        name
    );
    assert!(
        message["wire_hex"]
            .as_str()
            .unwrap()
            .contains("65761b5b33316d696ce280ae")
    );
}

#[test]
fn zero_application_message_limit_is_a_usage_error() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/dns-response.pcap");
    let path = path.to_str().unwrap();
    let output = run(&[
        "--output",
        "json",
        "dns-read",
        path,
        "--max-application-messages",
        "0",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let error = &parse_json(&output)["error"];
    assert_eq!(error["code"], "cli.analysis_limit");
    assert_eq!(error["kind"], "cli");
    assert!(
        error["message"].as_str().unwrap().contains("max_messages"),
        "{error}"
    );
}
