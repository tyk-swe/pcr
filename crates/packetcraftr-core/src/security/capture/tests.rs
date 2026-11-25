// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    analysis::Collector as _,
    budget::{Cancellation, Deadline},
    security::indicators::{Indicator, Kind, SCHEMA},
};
use std::time::{Duration, UNIX_EPOCH};

#[test]
fn threshold_validation_accepts_exact_boundaries() {
    for (options, field) in [
        (
            DnsOptions {
                window_seconds: 0,
                ..Default::default()
            },
            "window_seconds",
        ),
        (
            DnsOptions {
                min_responses: 0,
                ..Default::default()
            },
            "min_responses",
        ),
        (
            DnsOptions {
                min_labels: 0,
                ..Default::default()
            },
            "min_labels",
        ),
        (
            DnsOptions {
                min_label_length: 64,
                ..Default::default()
            },
            "min_label_length",
        ),
        (
            DnsOptions {
                nxdomain_ratio: f64::NAN,
                ..Default::default()
            },
            "nxdomain_ratio",
        ),
        (
            DnsOptions {
                nxdomain_ratio: 1.1,
                ..Default::default()
            },
            "nxdomain_ratio",
        ),
        (
            DnsOptions {
                min_entropy: f64::INFINITY,
                ..Default::default()
            },
            "min_entropy",
        ),
        (
            DnsOptions {
                min_entropy: -0.1,
                ..Default::default()
            },
            "min_entropy",
        ),
    ] {
        assert!(options.validate().unwrap_err().to_string().contains(field));
        assert!(
            Collector::new(
                Mode::Dns(options),
                Limits::default(),
                application::Limits::default(),
                crate::protocol::builtin::registry()
            )
            .is_err()
        );
    }
    for (options, field) in [
        (
            BeaconOptions {
                min_attempts: 2,
                ..Default::default()
            },
            "min_attempts",
        ),
        (
            BeaconOptions {
                min_interval_seconds: 0.0,
                ..Default::default()
            },
            "min_interval_seconds",
        ),
        (
            BeaconOptions {
                min_interval_seconds: f64::NAN,
                ..Default::default()
            },
            "min_interval_seconds",
        ),
        (
            BeaconOptions {
                max_cv: f64::INFINITY,
                ..Default::default()
            },
            "max_cv",
        ),
        (
            BeaconOptions {
                max_cv: 1.1,
                ..Default::default()
            },
            "max_cv",
        ),
    ] {
        assert!(options.validate().unwrap_err().to_string().contains(field));
        assert!(
            Collector::new(
                Mode::Beacons(options),
                Limits::default(),
                application::Limits::default(),
                crate::protocol::builtin::registry()
            )
            .is_err()
        );
    }
    for (ratio, entropy, length) in [(0.0, 0.0, 1), (1.0, 8.0, 63)] {
        assert!(
            DnsOptions {
                nxdomain_ratio: ratio,
                min_entropy: entropy,
                min_label_length: length,
                ..Default::default()
            }
            .validate()
            .is_ok()
        );
    }
    for max_cv in [0.0, 1.0] {
        assert!(
            BeaconOptions {
                min_attempts: 3,
                max_cv,
                ..Default::default()
            }
            .validate()
            .is_ok()
        );
    }
}

fn collector() -> Collector {
    let mut collector = Collector::new(
        Mode::Beacons(BeaconOptions::default()),
        Limits::default(),
        application::Limits::default(),
        crate::protocol::builtin::registry(),
    )
    .unwrap();
    for subject in ["first", "second"] {
        collector
            .output
            .add(Finding::new(
                "test",
                Severity::Low,
                subject,
                "summary",
                json!({"observed":true}),
                "review",
            ))
            .unwrap();
    }
    collector
}

#[test]
fn controlled_finalization_preserves_evidence() {
    let run = analysis::Summary::default();
    let expected_report = collector()
        .finalize(&run, &Deadline::new(Duration::MAX))
        .unwrap();
    let mut events = Vec::new();
    let report = collector()
        .finish(&run, &Deadline::new(Duration::from_secs(1)), &mut |event| {
            events.push(event);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        serde_json::to_value(&events).unwrap(),
        serde_json::to_value(&expected_report.findings).unwrap()
    );
    assert_eq!(
        serde_json::to_value(report).unwrap(),
        serde_json::to_value(expected_report).unwrap()
    );
    assert!(events.iter().all(|event| !event.complete));
}

#[test]
fn finalization_stops_on_errors_and_interrupts() {
    let run = analysis::Summary::default();
    let mut delivered = 0;
    let error = collector()
        .finish(&run, &Deadline::new(Duration::from_secs(1)), &mut |_| {
            delivered += 1;
            Err(BoundaryError::from_error(Error::Invalid(
                "sink refused".into(),
            )))
        })
        .unwrap_err();
    assert_eq!(delivered, 1);
    assert!(error.to_string().contains("sink refused"));
    assert!(
        collector()
            .finish(&run, &Deadline::immediate(None), &mut |_| panic!(
                "expired events must not be delivered"
            ))
            .is_err()
    );
    let cancellation = Cancellation::default();
    let deadline =
        Deadline::new(Duration::from_secs(1)).with_cancellation(Some(cancellation.clone()));
    let mut delivered = 0;
    assert!(
        collector()
            .finish(&run, &deadline, &mut |_| {
                delivered += 1;
                cancellation.cancel();
                Ok(())
            })
            .is_err()
    );
    assert_eq!(delivered, 1);
}

#[test]
fn constructed_hunts_validate_and_normalize() {
    let document = |id: &str, value: &str| Document {
        schema: SCHEMA.into(),
        indicators: vec![Indicator {
            id: id.into(),
            kind: Kind::Domain,
            value: value.into(),
        }],
    };
    for doc in [
        document("", "example.test"),
        document("dns", "."),
        Document {
            schema: "unknown".into(),
            indicators: vec![],
        },
    ] {
        assert!(
            Collector::new(
                Mode::Hunt(doc),
                Limits::default(),
                application::Limits::default(),
                crate::protocol::builtin::registry()
            )
            .is_err()
        );
    }
    let mut collector = Collector::new(
        Mode::Hunt(document("dns", "EXAMPLE.TEST.")),
        Limits::default(),
        application::Limits::default(),
        crate::protocol::builtin::registry(),
    )
    .unwrap();
    let Engine::Hunt(hunt) = &collector.engine else {
        panic!("a hunt document builds a hunt")
    };
    hunt.matches
        .dns_events(vec![dns_event("Example.TEST.")], &mut collector.output)
        .unwrap();
    let findings = &collector.output.report.findings;
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].indicator_id.as_deref(), Some("dns"));
}

#[test]
fn beacon_intervals_preserve_nanosecond_precision() {
    let options = BeaconOptions {
        min_attempts: 3,
        min_interval_seconds: 1e-10,
        max_cv: 0.0,
    };
    let mut collector = Collector::new(
        Mode::Beacons(options),
        Limits::default(),
        application::Limits::default(),
        crate::protocol::builtin::registry(),
    )
    .unwrap();
    let epoch = Duration::from_secs(1_800_000_000);
    let Engine::Beacons(beacons) = &mut collector.engine else {
        panic!("beacon options build a beacon collector")
    };
    beacons.groups.insert(
        (
            0,
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            443,
        ),
        beacons::BeaconGroup {
            times: vec![
                epoch,
                epoch + Duration::from_nanos(1),
                epoch + Duration::from_nanos(2),
            ],
            frames: vec![1, 2, 3],
        },
    );
    let report = collector
        .finalize(
            &analysis::Summary::default(),
            &crate::budget::Deadline::new(Duration::from_secs(1)),
        )
        .unwrap();
    assert_eq!(report.findings.len(), 1);
    assert_eq!(
        report.findings[0].evidence["mean_interval_seconds"],
        json!(1e-9)
    );
}

fn dns_event(name: &str) -> dns::Event {
    use crate::protocol::application::dns::{Dns, Question};
    let mut message = Dns::default();
    message.questions.push(Question {
        name: name.parse().unwrap(),
        query_type: 1,
        class: 1,
    });
    dns_message(1, message, 100)
}

fn flow() -> analysis::ScopedFlowKey {
    use crate::analysis::{FlowKey, ScopedFlowKey, scope::Interner};
    ScopedFlowKey {
        scope: Interner::default().intern(None, vec![]).unwrap(),
        flow: FlowKey {
            source: "192.0.2.1".parse().unwrap(),
            source_port: 1000,
            destination: "192.0.2.2".parse().unwrap(),
            destination_port: 53,
        },
    }
}

fn sources(number: u64, seconds: u64) -> analysis::provenance::SourceSet {
    use crate::analysis::provenance::{SourceFrame, Tracker};
    Tracker::new(4096, 8)
        .unwrap()
        .single(SourceFrame {
            number,
            timestamp: UNIX_EPOCH + Duration::from_secs(seconds),
        })
        .unwrap()
}

fn dns_message(
    index: u64,
    message: crate::protocol::application::dns::Dns,
    seconds: u64,
) -> dns::Event {
    dns::Event::Message(Box::new(dns::Message {
        index,
        transport: analysis::StreamTransport::Udp,
        stream: 1,
        generation: 0,
        flow: flow(),
        status: dns::Status::Complete,
        wire: bytes::Bytes::new(),
        declared_length: None,
        framing_bytes: bytes::Bytes::new(),
        dns: Some(message),
        error: None,
        sources: sources(index, seconds),
    }))
}

fn response(index: u64, rcode: u8, extended: Option<u8>) -> dns::Event {
    use crate::protocol::application::dns::{Dns, Edns, Record};
    let mut message = Dns::default();
    message.response = true;
    message.rcode = rcode;
    if let Some(extended_response_code) = extended {
        message.additionals.push(Record::opt(Edns {
            udp_payload_size: 1232,
            extended_response_code,
            version: 0,
            dnssec_ok: false,
            flags: 0,
            options: Vec::new(),
        }));
    }
    dns_message(index, message, 100)
}

fn transaction(status: dns::TransactionStatus, response: u64) -> dns::Event {
    dns::Event::Transaction(dns::Transaction {
        status,
        transport: analysis::StreamTransport::Udp,
        stream: 1,
        generation: 0,
        flow: flow(),
        dns_id: 0,
        queries: vec![response - 100],
        response: Some(response),
        original_response: None,
        first_query_latency: None,
        latest_query_latency: None,
        sources: sources(response, 100),
    })
}

fn group_dns(collector: &mut Collector, name: &str) -> Result<(), BoundaryError> {
    let Engine::Dns(anomalies) = &mut collector.engine else {
        panic!("DNS options build a DNS collector")
    };
    anomalies
        .grouping
        .events(vec![dns_event(name)], &mut collector.output)
}

fn dns_groups(collector: &Collector) -> &BTreeMap<dns_anomalies::DnsKey, dns_anomalies::DnsGroup> {
    let Engine::Dns(anomalies) = &collector.engine else {
        panic!("DNS options build a DNS collector")
    };
    &anomalies.grouping.groups
}

#[test]
fn dns_groups_inner_labels_within_budget() {
    let options = DnsOptions {
        min_label_length: 4,
        min_entropy: 1.0,
        min_labels: 1,
        ..Default::default()
    };
    let mut collector = Collector::new(
        Mode::Dns(options),
        Limits::default(),
        application::Limits::default(),
        crate::protocol::builtin::registry(),
    )
    .unwrap();
    group_dns(&mut collector, "a.aBcD.Example.test.").unwrap();
    let groups = dns_groups(&collector);
    assert!(
        groups
            .keys()
            .any(|key| key.3.as_deref() == Some("example.test."))
    );
    assert!(
        groups
            .values()
            .any(|group| group.labels.contains(b"abcd".as_slice()))
    );
    assert!(!groups.keys().any(|key| key.3.as_deref() == Some(".")));
    group_dns(&mut collector, "aBcD.").unwrap();
    assert!(
        !dns_groups(&collector)
            .keys()
            .any(|key| key.3.as_deref() == Some("."))
    );
    let mut bounded = Collector::new(
        Mode::Dns(options),
        Limits {
            max_groups: 1,
            ..Default::default()
        },
        application::Limits::default(),
        crate::protocol::builtin::registry(),
    )
    .unwrap();
    assert!(group_dns(&mut bounded, "aBcD.eFgH.test.").is_err());
}

fn anomalies(options: DnsOptions) -> Collector {
    Collector::new(
        Mode::Dns(options),
        Limits::default(),
        application::Limits::default(),
        crate::protocol::builtin::registry(),
    )
    .unwrap()
}

fn feed(collector: &mut Collector, events: Vec<dns::Event>) {
    let Engine::Dns(anomalies) = &mut collector.engine else {
        panic!("DNS options build a DNS collector")
    };
    anomalies
        .grouping
        .events(events, &mut collector.output)
        .unwrap();
}

fn observed_run() -> analysis::Summary {
    analysis::Summary {
        frames_matched: 1,
        ..Default::default()
    }
}

#[test]
fn nxdomain_ratio_counts_matched_responses_by_full_response_code_and_window() {
    use dns::TransactionStatus::{Matched, Unanswered};
    let mut collector = anomalies(DnsOptions {
        min_responses: 3,
        nxdomain_ratio: 0.6,
        ..Default::default()
    });
    feed(
        &mut collector,
        vec![
            response(110, 3, None),
            response(111, 3, Some(1)),
            response(112, 3, Some(0)),
            response(113, 0, None),
            transaction(Matched, 110),
            transaction(Matched, 111),
            transaction(Matched, 112),
            transaction(Unanswered, 113),
        ],
    );
    let report = collector
        .finalize(&observed_run(), &Deadline::new(Duration::from_secs(1)))
        .unwrap();
    let [finding] = report.findings.as_slice() else {
        panic!("expected one finding: {:?}", report.findings);
    };
    assert_eq!(finding.rule_id, "dns.nxdomain_ratio");
    assert_eq!(finding.subject, "192.0.2.1");
    assert_eq!(finding.frames, [110, 111, 112]);
    assert_eq!(finding.evidence["responses"], 3);
    assert_eq!(finding.evidence["nxdomain"], 2);
    assert_eq!(finding.evidence["window_start_seconds"], 60);
    assert_eq!(
        report.completeness.reasons,
        ["DNS transactions include unanswered, orphan, or duplicate messages"]
    );
}

#[test]
fn label_rule_groups_long_high_entropy_labels_by_the_following_domain() {
    let mut collector = anomalies(DnsOptions {
        min_label_length: 4,
        min_entropy: 1.0,
        min_labels: 3,
        ..Default::default()
    });
    feed(
        &mut collector,
        [
            "abcd.zone.test.",
            "dcba.zone.test.",
            "abab.zone.test.",
            "abc.zone.test.",
            "aaaa.zone.test.",
        ]
        .into_iter()
        .map(dns_event)
        .collect(),
    );
    let groups: Vec<_> = dns_groups(&collector)
        .iter()
        .map(|(key, group)| {
            let labels: Vec<_> = group
                .labels
                .iter()
                .map(|label| String::from_utf8(label.clone()).unwrap())
                .collect();
            (key.3.clone().unwrap(), labels)
        })
        .collect();
    assert_eq!(
        groups,
        [
            ("test.".to_owned(), vec!["zone".to_owned()]),
            (
                "zone.test.".to_owned(),
                ["abab", "abcd", "dcba"].map(str::to_owned).to_vec()
            ),
        ]
    );
    let report = collector
        .finalize(&observed_run(), &Deadline::new(Duration::from_secs(1)))
        .unwrap();
    let [finding] = report.findings.as_slice() else {
        panic!("expected one finding: {:?}", report.findings);
    };
    assert_eq!(finding.rule_id, "dns.high_entropy_labels");
    assert_eq!(finding.evidence["suffix"], "zone.test.");
    assert_eq!(finding.evidence["distinct_labels"], 3);
    assert_eq!(finding.evidence["window_start_seconds"], 60);
}

#[test]
fn run_evidence_gaps_are_noted_in_order_and_mark_findings_incomplete() {
    let complete = collector()
        .finalize(&observed_run(), &Deadline::new(Duration::from_secs(1)))
        .unwrap();
    assert!(complete.completeness.complete);
    let mut run = analysis::Summary {
        source_outcomes_omitted: 1,
        ..Default::default()
    };
    run.clock.regressions = 1;
    let report = collector()
        .finalize(&run, &Deadline::new(Duration::from_secs(1)))
        .unwrap();
    assert_eq!(
        report.completeness.reasons,
        [
            "no frames matched the selected capture scope",
            "capture reassembly has incomplete source evidence",
            "capture clock regressions observed; beacon timing conclusions suppressed",
        ]
    );
    assert!(report.findings.iter().all(|finding| !finding.complete));
}

#[test]
fn malformed_messages_and_stream_issues_are_noted() {
    let mut collector = anomalies(DnsOptions::default());
    let dns::Event::Message(mut malformed) = dns_event("zone.test.") else {
        unreachable!()
    };
    malformed.status = dns::Status::Malformed;
    malformed.dns = None;
    feed(
        &mut collector,
        vec![
            dns::Event::Message(malformed),
            dns::Event::Issue(dns::StreamIssue {
                number: 1,
                flow: flow(),
                stream: 1,
                status: dns::Status::Reset,
            }),
        ],
    );
    assert_eq!(collector.output.observations, 1);
    assert_eq!(
        collector.output.report.completeness.reasons,
        [
            "incomplete or malformed DNS messages",
            "DNS stream has missing or conflicting bytes"
        ]
    );
}

#[test]
fn only_beacons_skip_tcp_stream_events() {
    let needs = |mode| {
        Collector::new(
            mode,
            Limits::default(),
            application::Limits::default(),
            crate::protocol::builtin::registry(),
        )
        .unwrap()
        .needs()
    };
    assert!(!needs(Mode::Beacons(BeaconOptions::default())).tcp_events);
    assert!(needs(Mode::Dns(DnsOptions::default())).tcp_events);
}

#[test]
fn fragmented_tls_hunt_attributes_all_contributing_frames() {
    use crate::{
        codec::Addresses,
        frame::{Frame, LinkType},
        layer::Raw,
        packet::Packet,
        protocol::{builtin, link::Ethernet, network::Ipv4, transport::Tcp},
    };
    use bytes::Bytes;

    fn decode_hex(input: &str) -> Vec<u8> {
        (0..input.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&input[index..index + 2], 16).unwrap())
            .collect()
    }

    let tls = decode_hex(concat!(
        "16030300c9010000c50303111111111111111111111111111111111111111111111111111111111111111120",
        "22222222222222222222222222222222222222222222222222222222222222220008130113021303c02f010000",
        "740000001500130000106170692e6578616d706c652e746573740010000e000c02683208687474702f312e",
        "31000a00060004001d0017000d00080006040308040401002b00050403040303003300260024001d002099",
        "99999999999999999999999999999999999999999999999999999999999999"
    ));
    assert_eq!(tls.len(), 206);
    let registry = builtin::registry();
    let builder = crate::build::Builder::new(registry.clone());
    let mut writer = crate::capture_file::Writer::pcap_with_options(
        Vec::new(),
        LinkType::ETHERNET,
        Default::default(),
    )
    .unwrap();
    for (seconds, sequence, flags, payload) in [
        (0, 1000, Tcp::SYN, &b""[..]),
        (1, 1001, Tcp::ACK, &tls[..100]),
        (2, 1101, Tcp::ACK, &tls[100..]),
    ] {
        let mut packet = Packet::default();
        packet.push(Ethernet::default());
        packet.push(Ipv4 {
            source: "192.0.2.1".parse().unwrap(),
            destination: "198.51.100.2".parse().unwrap(),
            ..Default::default()
        });
        packet.push(Tcp {
            source_port: 54321,
            destination_port: 443,
            sequence,
            flags,
            ..Default::default()
        });
        if !payload.is_empty() {
            packet.push(Raw::new(Bytes::copy_from_slice(payload)));
        }
        let built = builder
            .build(packet, Addresses::default(), Default::default())
            .unwrap();
        let frame = Frame::new(
            Some(UNIX_EPOCH + Duration::from_secs(seconds)),
            LinkType::ETHERNET,
            built.bytes,
        )
        .unwrap();
        writer.write_frame(&frame).unwrap();
    }
    let capture = writer.into_inner();
    let indicators = Document {
        schema: SCHEMA.into(),
        indicators: vec![Indicator {
            id: "tls-sni".into(),
            kind: Kind::Domain,
            value: "api.example.test".into(),
        }],
    };
    let collector = Collector::new(
        Mode::Hunt(indicators),
        Limits::default(),
        application::Limits::default(),
        registry.clone(),
    )
    .unwrap();
    let mut reader =
        crate::capture_file::Reader::with_limits(&capture[..], Default::default()).unwrap();

    let outcome = crate::analysis::Session::new(registry, Default::default(), collector)
        .run(&mut reader, |_| Ok(()), |_| Ok(()))
        .unwrap();

    let finding = outcome
        .summary
        .findings
        .iter()
        .find(|finding| finding.indicator_id.as_deref() == Some("tls-sni"))
        .expect("fragmented TLS ClientHello did not match the hunt indicator");
    assert_eq!(finding.frames, [2, 3]);
}

#[test]
fn hunts_match_indicators_in_every_kind_of_dns_answer() {
    use crate::protocol::application::dns::{Dns, Record, RecordValue};
    let indicators = Document {
        schema: SCHEMA.into(),
        indicators: [
            ("v4", Kind::Ip, "192.0.2.10"),
            ("v6", Kind::Ip, "2001:db8::10"),
            ("alias", Kind::Domain, "alias.test"),
            ("primary", Kind::Domain, "ns.test"),
            ("mailbox", Kind::Domain, "admin.test"),
        ]
        .into_iter()
        .map(|(id, kind, value)| Indicator {
            id: id.into(),
            kind,
            value: value.into(),
        })
        .collect(),
    };
    let mut collector = Collector::new(
        Mode::Hunt(indicators),
        Limits::default(),
        application::Limits::default(),
        crate::protocol::builtin::registry(),
    )
    .unwrap();
    let owner = |name: &str| name.parse().unwrap();
    let mut message = Dns::default();
    message.response = true;
    message.answers = [
        RecordValue::A("192.0.2.10".parse().unwrap()),
        RecordValue::Aaaa("2001:db8::10".parse().unwrap()),
        RecordValue::Cname(owner("alias.test.")),
        RecordValue::Soa {
            primary_name_server: owner("ns.test."),
            responsible_mailbox: owner("admin.test."),
            serial: 1,
            refresh: 1,
            retry: 1,
            expire: 1,
            minimum: 1,
        },
    ]
    .into_iter()
    .map(|value| Record {
        owner: owner("answer.example."),
        class: 1,
        ttl: 60,
        value,
    })
    .collect();
    let Engine::Hunt(hunt) = &collector.engine else {
        unreachable!()
    };
    hunt.matches
        .dns_events(vec![dns_message(1, message, 100)], &mut collector.output)
        .unwrap();
    let matched: Vec<_> = collector
        .output
        .report
        .findings
        .iter()
        .map(|finding| {
            (
                finding.indicator_id.clone().unwrap(),
                finding.evidence["context"]["protocol"].clone(),
            )
        })
        .collect();
    assert_eq!(
        matched,
        [
            ("v4".to_owned(), json!("dns_answer")),
            ("v6".to_owned(), json!("dns_answer")),
            ("alias".to_owned(), json!("dns_rdata")),
            ("primary".to_owned(), json!("dns_rdata")),
            ("mailbox".to_owned(), json!("dns_rdata")),
        ]
    );
}
