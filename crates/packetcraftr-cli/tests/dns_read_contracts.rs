// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::{assert_contiguous, parse_json, parse_ndjson, run, run_success};

use packetcraftr_core::capture_file::{Format, Writer};
use packetcraftr_core::frame::{Frame, LinkType};

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

/// `--dns-port` adds nonstandard services; port 53 is always analyzed.
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
    let path = path.to_str().unwrap();
    let document = parse_json(&run_success(&["--output", "json", "dns-read", path]));
    let total: usize = ["messages", "transactions", "issues"]
        .iter()
        .flat_map(|key| document["result"][key].as_array().unwrap().iter())
        .map(|value| serde_json::to_vec(value).unwrap().len())
        .sum();
    let command = "dns-read";
    let event_collections = [
        ("dns_message", "messages"),
        ("dns_transaction", "transactions"),
        ("dns_stream_issue", "issues"),
    ];
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
    let error_message = "application output exceeds --max-application-output-bytes";
    let exact = total.to_string();
    let under = (total - 1).to_string();
    for format in ["json", "ndjson", "text"] {
        let success = run_success(&[
            "--output",
            format,
            command,
            path,
            "--max-application-output-bytes",
            &exact,
        ]);
        match format {
            "json" => assert_eq!(parse_json(&success)["result"], document["result"]),
            "ndjson" => {
                let records = parse_ndjson(&success);
                assert_contiguous(&records);
                assert_eq!(records.last().unwrap()["event"], "complete");
                for &(event, key) in &event_collections {
                    let values = records
                        .iter()
                        .filter(|record| record["event"] == event)
                        .map(|record| record["result"].clone())
                        .collect();
                    assert_eq!(serde_json::Value::Array(values), document["result"][key]);
                }
            }
            "text" => assert_eq!(String::from_utf8(success.stdout).unwrap(), expected_text),
            _ => unreachable!(),
        }
        let failure = run(&[
            "--output",
            format,
            command,
            path,
            "--max-application-output-bytes",
            &under,
        ]);
        assert_eq!(failure.status.code(), Some(6), "format {format}");
        let error = match format {
            "json" => parse_json(&failure)["error"].clone(),
            "ndjson" => {
                let records = parse_ndjson(&failure);
                assert_contiguous(&records);
                assert_eq!(records.last().unwrap()["event"], "error");
                assert_eq!(
                    records
                        .iter()
                        .filter(|record| record["event"] == "error")
                        .count(),
                    1
                );
                assert!(records.iter().all(|record| record["event"] != "complete"));
                records.last().unwrap()["error"].clone()
            }
            "text" => continue,
            _ => unreachable!(),
        };
        assert_eq!(error["code"], "policy.denied");
        assert_eq!(error["message"], error_message);
    }
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

/// One IPv4/UDP DNS response from 192.0.2.53 whose question name and TXT
/// answer carry terminal escape and bidirectional-override bytes.
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

/// Captured DNS names and record text reach the terminal escaped: no escape,
/// control, or bidirectional-override character survives into text output,
/// from `dns-read` or from `read --dissect`.
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
    // The machine document keeps the exact name for consumers that escape
    // for their own medium.
    let document = parse_json(&run_success(&["--output", "json", "dns-read", path]));
    assert_eq!(document["result"]["summary"]["complete_messages"], 1);
}
