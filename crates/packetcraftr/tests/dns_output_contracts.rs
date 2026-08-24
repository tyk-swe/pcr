// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr::core::diagnostic::Diagnostic;
use packetcraftr::core::frame::{Frame, LinkType};
use packetcraftr::output::dns as dns_output;
use packetcraftr::{Stats, dns};

const TRANSACTION_ID: u16 = 0x4a5b;
const RESPONSE: u16 = 0x8000;
const AUTHORITATIVE: u16 = 0x0400;
const RECURSION_DESIRED: u16 = 0x0100;
const RECURSION_AVAILABLE: u16 = 0x0080;
const AUTHENTICATED_DATA: u16 = 0x0020;
const CHECKING_DISABLED: u16 = 0x0010;

#[derive(Clone)]
struct WireRecord {
    owner: Vec<u8>,
    type_code: u16,
    class: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

fn wire_name(value: &str) -> Vec<u8> {
    if value == "." {
        return vec![0];
    }
    let mut output = Vec::new();
    for label in value.trim_end_matches('.').split('.') {
        output.push(u8::try_from(label.len()).expect("fixture label fits DNS length"));
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    output
}

fn record(type_code: u16, rdata: Vec<u8>) -> WireRecord {
    WireRecord {
        owner: vec![0xc0, 0x0c],
        type_code,
        class: 1,
        ttl: 300,
        rdata,
    }
}

fn push_record(message: &mut Vec<u8>, record: &WireRecord) {
    message.extend_from_slice(&record.owner);
    message.extend_from_slice(&record.type_code.to_be_bytes());
    message.extend_from_slice(&record.class.to_be_bytes());
    message.extend_from_slice(&record.ttl.to_be_bytes());
    message.extend_from_slice(
        &u16::try_from(record.rdata.len())
            .expect("fixture RDATA fits u16")
            .to_be_bytes(),
    );
    message.extend_from_slice(&record.rdata);
}

fn response_message(answers: &[WireRecord], additionals: &[WireRecord]) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&TRANSACTION_ID.to_be_bytes());
    message.extend_from_slice(
        &(RESPONSE
            | AUTHORITATIVE
            | RECURSION_DESIRED
            | RECURSION_AVAILABLE
            | AUTHENTICATED_DATA
            | CHECKING_DISABLED
            | 2)
        .to_be_bytes(),
    );
    message.extend_from_slice(&1_u16.to_be_bytes());
    message.extend_from_slice(
        &u16::try_from(answers.len())
            .expect("fixture answer count")
            .to_be_bytes(),
    );
    message.extend_from_slice(&0_u16.to_be_bytes());
    message.extend_from_slice(
        &u16::try_from(additionals.len())
            .expect("fixture additional count")
            .to_be_bytes(),
    );
    message.extend_from_slice(&wire_name("example.test."));
    message.extend_from_slice(&dns::QueryType::Any.code().to_be_bytes());
    message.extend_from_slice(&1_u16.to_be_bytes());
    for answer in answers {
        push_record(&mut message, answer);
    }
    for additional in additionals {
        push_record(&mut message, additional);
    }
    message
}

fn representative_response() -> dns::ValidatedResponse {
    let mut soa = wire_name("ns.example.test.");
    soa.extend_from_slice(&wire_name("hostmaster.example.test."));
    for value in [1_u32, 2, 3, 4, 5] {
        soa.extend_from_slice(&value.to_be_bytes());
    }
    let mut mx = 10_u16.to_be_bytes().to_vec();
    mx.extend_from_slice(&wire_name("mail.example.test."));
    let mut srv = Vec::new();
    for value in [1_u16, 2, 443] {
        srv.extend_from_slice(&value.to_be_bytes());
    }
    srv.extend_from_slice(&wire_name("service.example.test."));
    let answers = vec![
        record(1, vec![192, 0, 2, 1]),
        record(
            28,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
                .octets()
                .to_vec(),
        ),
        record(5, wire_name("alias.example.test.")),
        record(15, mx),
        record(2, wire_name("ns.example.test.")),
        record(12, wire_name("ptr.example.test.")),
        record(6, soa),
        record(33, srv),
        record(16, vec![3, b'a', b'b', b'c', 1, 0xff]),
        record(65_000, vec![9, 8, 7]),
    ];
    let opt = WireRecord {
        owner: wire_name("."),
        type_code: 41,
        class: 1_232,
        ttl: (1_u32 << 24) | 0x8000,
        rdata: vec![0, 10, 0, 2, 0xaa, 0xbb],
    };
    let message = response_message(&answers, &[opt]);
    let mut response = dns::decode_response(
        &message,
        "example.test",
        dns::QueryType::Any,
        TRANSACTION_ID,
        dns::Limits::default(),
    )
    .expect("representative DNS response decodes");
    let edns = response.metadata.edns.clone().expect("EDNS metadata");
    response.additionals.push(dns::Record {
        owner: response.answers[0].owner.clone(),
        class: 1_232,
        ttl: 0,
        value: dns::RecordValue::Opt(edns),
    });
    response.rejected_records.push(dns::RejectedRecord {
        section: dns::Section::Authority,
        index: 4,
        owner: "ignored.example.test.".to_owned(),
        type_code: 65_001,
        reason: "unrelated fixture record".to_owned(),
    });
    response.metadata.rejected_record_count = 1;
    response
}

fn evidence_frame() -> Frame {
    Frame::new(
        UNIX_EPOCH + Duration::from_secs(2),
        LinkType::IPV4,
        vec![0x45, 0, 0, 20],
    )
    .expect("bounded evidence frame")
}

fn attempt_evidence() -> dns::AttemptEvidence {
    dns::AttemptEvidence {
        attempt: 1,
        server_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
        source_port: 49_152,
        status: dns::Outcome::Response,
        sent_at: UNIX_EPOCH + Duration::from_secs(1),
        received_at: Some(UNIX_EPOCH + Duration::from_secs(2)),
        latency: Some(Duration::from_secs(1)),
        response: Some(evidence_frame()),
        response_code: Some(18),
        reason: "validated DNS response".to_owned(),
    }
}

fn stats() -> Stats {
    Stats {
        packets_attempted: 2,
        packets_completed: 1,
        bytes: 128,
        elapsed: Duration::from_millis(25),
        capture: packetcraftr::netio::capture::Statistics {
            received_frames: 2,
            received_bytes: 256,
            ..packetcraftr::netio::capture::Statistics::default()
        },
    }
}

fn event_context() -> Arc<dns::EventContext> {
    Arc::new(dns::EventContext {
        server: Arc::from("resolver.example.test"),
        server_port: 53,
        query_name: Arc::from("example.test"),
        query_type: dns::QueryType::Any,
    })
}

#[test]
fn dns_aggregate_output_preserves_all_record_shapes_metadata_and_evidence() {
    let diagnostic = Diagnostic::warning("dns.fixture", "fixture warning");
    let (output, diagnostics, converted_stats) = dns_output::Result::try_from_dns(dns::Result {
        server: "resolver.example.test".to_owned(),
        server_port: 53,
        resolved_addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))],
        query_name: "example.test".to_owned(),
        query_type: dns::QueryType::Any,
        transaction_id: TRANSACTION_ID,
        outcome: dns::Outcome::Response,
        response: Some(representative_response()),
        attempts: vec![attempt_evidence()],
        undecoded: vec![dns::UndecodedEvidence {
            attempt: 2,
            frame: evidence_frame(),
        }],
        diagnostics: vec![diagnostic.clone()],
        stats: stats(),
    })
    .expect("bounded DNS result converts");

    assert_eq!(diagnostics, [diagnostic]);
    assert_eq!(converted_stats.packets_attempted, 2);
    assert_eq!(converted_stats.capture.received_frames, 2);
    assert_eq!(output.response_code, Some(18));
    assert_eq!(output.response_code_name.as_deref(), Some("bad_time"));
    assert_eq!(output.authoritative, Some(true));
    assert_eq!(output.truncated, Some(false));
    assert_eq!(output.recursion_desired, Some(true));
    assert_eq!(output.recursion_available, Some(true));
    assert_eq!(output.authenticated_data, Some(true));
    assert_eq!(output.checking_disabled, Some(true));
    assert_eq!(output.rejected_record_count, 1);
    assert_eq!(output.rejected_records.len(), 1);
    assert_eq!(output.attempts[0].attempt, 1);
    assert_eq!(
        output.attempts[0]
            .received_at
            .expect("received time")
            .unix_seconds,
        2
    );
    assert_eq!(
        output.attempts[0]
            .frame
            .as_ref()
            .expect("response frame")
            .captured_length,
        4_u32
    );
    assert_eq!(output.undecoded[0].attempt, 2);

    let json = serde_json::to_value(&output).expect("DNS output serializes");
    let record_types = json["answers"]
        .as_array()
        .expect("answer array")
        .iter()
        .map(|record| record["type"].as_str().expect("record type"))
        .collect::<Vec<_>>();
    assert_eq!(
        record_types,
        [
            "a", "aaaa", "cname", "mx", "ns", "ptr", "soa", "srv", "txt", "unknown"
        ]
    );
    assert_eq!(
        json["answers"][8]["strings"],
        serde_json::json!(["abc", "�"])
    );
    assert_eq!(
        json["answers"][8]["strings_hex"],
        serde_json::json!(["616263", "ff"])
    );
    assert_eq!(json["answers"][9]["rdata_hex"], "090807");
    assert_eq!(json["additionals"][0]["type"], "opt");
    assert_eq!(
        json["additionals"][0]["edns"]["options"][0]["data_hex"],
        "aabb"
    );
    assert_eq!(json["edns"]["udp_payload_size"], 1_232);
    assert_eq!(json["edns"]["extended_response_code"], 1);
    assert_eq!(json["edns"]["dnssec_ok"], true);
}

#[test]
fn dns_progressive_outputs_cover_every_event_and_complete_metadata_shape() {
    let context = event_context();
    let response = representative_response();
    let record = response.answers[0].clone();
    let rejected = response.rejected_records[0].clone();

    let domain_events = vec![
        dns::Event::Attempt {
            context: Arc::clone(&context),
            evidence: attempt_evidence(),
        },
        dns::Event::Record {
            attempt: 1,
            context: Arc::clone(&context),
            section: dns::Section::Answer,
            record,
        },
        dns::Event::Rejected {
            attempt: 1,
            context,
            record: rejected,
        },
        dns::Event::Undecoded(dns::UndecodedEvidence {
            attempt: 2,
            frame: evidence_frame(),
        }),
    ];
    let expected_kinds = ["attempt", "record", "rejected", "undecoded"];
    for (event, expected_kind) in domain_events.into_iter().zip(expected_kinds) {
        let (event, diagnostics) =
            dns_output::Event::try_from_dns(event).expect("progressive event converts");
        assert!(diagnostics.is_empty());
        assert_eq!(
            serde_json::to_value(event).expect("event serializes")["event"],
            expected_kind
        );
    }

    let diagnostic = Diagnostic::warning("dns.progressive_fixture", "fixture warning");
    let (event, diagnostics) =
        dns_output::Event::try_from_dns(dns::Event::Diagnostic(diagnostic.clone()))
            .expect("diagnostic event converts");
    assert!(matches!(event, dns_output::Event::Diagnostic));
    assert_eq!(diagnostics, [diagnostic]);

    let (complete, diagnostics, converted_stats) =
        dns_output::Event::complete_from_dns(dns::Summary {
            server: "resolver.example.test".to_owned(),
            server_port: 53,
            resolved_addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))],
            query_name: "example.test".to_owned(),
            query_type: dns::QueryType::Any,
            transaction_id: TRANSACTION_ID,
            outcome: dns::Outcome::Response,
            response: Some(response.metadata),
            diagnostics: Vec::new(),
            stats: stats(),
        });
    assert!(diagnostics.is_empty());
    assert_eq!(converted_stats.bytes, 128);
    let complete = serde_json::to_value(complete).expect("complete event serializes");
    assert_eq!(complete["event"], "complete");
    assert_eq!(complete["response_code"], 18);
    assert_eq!(complete["response_code_name"], "bad_time");
    assert_eq!(complete["rejected_record_count"], 1);
}

#[test]
fn dns_timeout_output_omits_response_only_fields() {
    let (output, diagnostics, _) = dns_output::Result::try_from_dns(dns::Result {
        server: "resolver.example.test".to_owned(),
        server_port: 53,
        resolved_addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))],
        query_name: "example.test".to_owned(),
        query_type: dns::QueryType::A,
        transaction_id: TRANSACTION_ID,
        outcome: dns::Outcome::Timeout,
        response: None,
        attempts: Vec::new(),
        undecoded: Vec::new(),
        diagnostics: Vec::new(),
        stats: Stats::default(),
    })
    .expect("timeout output converts");
    assert!(diagnostics.is_empty());
    assert!(output.answers.is_empty());

    let json = serde_json::to_value(output).expect("timeout output serializes");
    for response_only in [
        "response_code",
        "response_code_name",
        "edns",
        "authoritative",
        "truncated",
        "recursion_desired",
        "recursion_available",
        "authenticated_data",
        "checking_disabled",
    ] {
        assert!(
            json.get(response_only).is_none(),
            "{response_only} must be omitted"
        );
    }

    let (complete, diagnostics, _) = dns_output::Event::complete_from_dns(dns::Summary {
        server: "resolver.example.test".to_owned(),
        server_port: 53,
        resolved_addresses: Vec::new(),
        query_name: "example.test".to_owned(),
        query_type: dns::QueryType::A,
        transaction_id: TRANSACTION_ID,
        outcome: dns::Outcome::Timeout,
        response: None,
        diagnostics: Vec::new(),
        stats: Stats::default(),
    });
    assert!(diagnostics.is_empty());
    let complete = serde_json::to_value(complete).expect("complete timeout serializes");
    assert!(complete.get("response_code").is_none());
    assert_eq!(complete["rejected_record_count"], 0);
}
