// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The `packetcraftr.rewrite/v1` and `/v2` documents and ordered rule
//! application.

use packetcraftr_core::{
    build::Builder,
    decode::Dissector,
    error::{BoundaryError, Classified, Kind},
    frame::{Frame, LinkType},
    layer::Raw,
    packet::Packet,
    protocol::{builtin, network::Ipv4, transport::Udp},
    transform::{
        ChecksumMode, FieldAssignment, HeaderRewrite, RewriteLimits, VlanRewrite,
        rules::{self, Rules},
    },
};
use serde_json::json;
use std::time::UNIX_EPOCH;

const LAB_HOST: &str = include_str!("../../../examples/documents/rewrite-lab-host.json");
const FIELD_EDITS: &str = include_str!("../../../examples/documents/rewrite-field-edits.json");

fn parse(document: &[u8]) -> Result<Rules, rules::Error> {
    Rules::parse(document, ChecksumMode::Repair, &builtin::registry())
}

fn parse_json(document: serde_json::Value) -> Result<Rules, rules::Error> {
    parse(&serde_json::to_vec(&document).unwrap())
}

fn udp_frame(ttl: u8) -> Frame {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: "192.0.2.1".parse().unwrap(),
        destination: "198.51.100.2".parse().unwrap(),
        ttl,
        ..Default::default()
    });
    packet.push(Udp {
        source_port: 40000,
        destination_port: 40001,
        ..Default::default()
    });
    packet.push(Raw::new(vec![1, 2, 3, 4]));
    let built = Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap();
    Frame::new(UNIX_EPOCH, LinkType::IPV4, built.bytes).unwrap()
}

/// The published error: its code, kind, message, and causes.
fn published(error: &rules::Error) -> (&'static str, Kind, String, Vec<String>) {
    let classification = error.classification();
    (
        classification.code,
        classification.kind,
        error.to_string(),
        error.causes(),
    )
}

#[test]
fn the_published_examples_read_as_ordered_rules() {
    let patches = parse(LAB_HOST.as_bytes()).unwrap();
    assert_eq!(patches.len(), 2);
    assert!(patches.has_header_edits());
    assert!(!patches.has_field_edits());
    let filters: Vec<_> = patches.iter().map(|rule| rule.filter.as_deref()).collect();
    assert_eq!(
        filters,
        [
            Some("ipv4.source == 192.0.2.1"),
            Some("ipv4.destination == 192.0.2.1")
        ]
    );
    assert_eq!(
        patches.iter().next().unwrap().patch,
        HeaderRewrite {
            source_ip: Some("192.0.2.9".parse().unwrap()),
            source_port: Some(49000),
            ..Default::default()
        }
    );

    let assignments = parse(FIELD_EDITS.as_bytes()).unwrap();
    assert_eq!(assignments.len(), 2);
    assert!(assignments.has_field_edits());
    assert!(!assignments.has_header_edits());
    assert_eq!(assignments.maximum_growth(), 0);
}

#[test]
fn document_refusals_keep_their_published_codes_and_messages() {
    const COUNT: &str = "rewrite rules hold {} rules; expected 1 to 64";
    let count = |rules: usize| COUNT.replace("{}", &rules.to_string());
    let usage = |message: &str| ("cli.error", Kind::Usage, message.to_owned(), Vec::new());
    let patch = json!({"patch": {"source_port": 1}});
    for (document, expected) in [
        (
            json!({"schema": "packetcraftr.rewrite/v3", "rules": [patch]}),
            usage(
                "unsupported rewrite rules schema packetcraftr.rewrite/v3; \
                 expected packetcraftr.rewrite/v1 or packetcraftr.rewrite/v2",
            ),
        ),
        (
            json!({"schema": "packetcraftr.rewrite/v1", "rules": []}),
            usage(&count(0)),
        ),
        (
            json!({"schema": "packetcraftr.rewrite/v1", "rules": vec![patch.clone(); 65]}),
            usage(&count(65)),
        ),
        (
            json!({"schema": "packetcraftr.rewrite/v2", "rules": []}),
            usage(&count(0)),
        ),
        (
            json!({"schema": "packetcraftr.rewrite/v1", "rules": [{"patch": {}}]}),
            usage("rewrite rules cannot contain empty patches"),
        ),
        (
            json!({"schema": "packetcraftr.rewrite/v2", "rules": [{"assign": []}]}),
            usage("rewrite rules cannot contain empty assignments"),
        ),
        (
            json!({"schema": "packetcraftr.rewrite/v2", "rules": [{"assign": ["ipv4.nope=1"]}]}),
            usage("invalid packet transform input: field edit names an unknown field"),
        ),
        (
            json!({"schema": "packetcraftr.rewrite/v1", "rules": [{"patch": {
                "source_ip": "192.0.2.1", "destination_ip": "2001:db8::1"
            }}]}),
            (
                "packet.transform_input",
                Kind::Packet,
                "invalid packet transform input: rewrite addresses use different IP families"
                    .to_owned(),
                Vec::new(),
            ),
        ),
    ] {
        let error = parse_json(document.clone()).expect_err("refused");
        assert_eq!(published(&error), expected, "{document}");
    }
    assert!(
        parse_json(json!({"schema": "packetcraftr.rewrite/v1", "rules": vec![patch; 64]})).is_ok()
    );
}

#[test]
fn syntax_refusals_name_the_parser_reason_once() {
    for document in [
        &b"{not json"[..],
        br#"{"schema": "packetcraftr.rewrite/v1", "rules": [{"assign": ["ipv4.ttl=1"]}]}"#,
        br#"{"schema": "packetcraftr.rewrite/v2", "rules": [{"patch": {"source_port": 1}}]}"#,
    ] {
        let error = parse(document).expect_err("refused");
        let (code, kind, message, causes) = published(&error);
        assert_eq!((code, kind), ("cli.error", Kind::Usage));
        assert_eq!(message, "invalid rewrite rules");
        assert_eq!(causes.len(), 1, "{causes:?}");
        assert!(!causes[0].is_empty());
        assert!(std::error::Error::source(&error).is_some());
    }
}

#[test]
fn an_oversized_document_is_refused_before_it_is_read() {
    let document = vec![b' '; rules::MAX_REWRITE_DOCUMENT_BYTES + 1];
    assert!(matches!(
        parse(&document),
        Err(rules::Error::DocumentSize { actual, limit })
            if actual == limit + 1
    ));
}

#[test]
fn a_single_rule_validates_its_patch_before_compiling_assignments() {
    let registry = builtin::registry();
    let assignments: Vec<FieldAssignment> = vec!["ipv4.nope=1".parse().unwrap()];
    let mixed = HeaderRewrite {
        source_ip: Some("192.0.2.1".parse().unwrap()),
        destination_ip: Some("2001:db8::1".parse().unwrap()),
        ..Default::default()
    };
    let error = Rules::single(None, mixed, &assignments, ChecksumMode::Repair, &registry)
        .expect_err("mixed families");
    assert!(matches!(error, rules::Error::Patch(_)), "{error:?}");
    let error = Rules::single(
        None,
        HeaderRewrite::default(),
        &assignments,
        ChecksumMode::Repair,
        &registry,
    )
    .expect_err("unknown field");
    assert!(matches!(error, rules::Error::Assignment(_)), "{error:?}");
    assert_eq!(error.classification().code, "cli.error");

    let vlans = Rules::single(
        Some("udp".to_owned()),
        HeaderRewrite {
            vlans: Some(vec![
                VlanRewrite {
                    ether_type: 0x8100,
                    identifier: 7,
                    priority: 0,
                    drop_eligible: false,
                };
                3
            ]),
            ..Default::default()
        },
        &[],
        ChecksumMode::Repair,
        &registry,
    )
    .unwrap();
    assert_eq!(vlans.maximum_growth(), 12);
    assert!(!vlans.has_field_edits());
}

#[test]
fn rules_apply_in_order_and_select_against_the_original_frame() {
    let rules = parse_json(json!({
        "schema": "packetcraftr.rewrite/v2",
        "rules": [
            {"filter": "first", "assign": ["ipv4.ttl=63"]},
            {"filter": "skipped", "assign": ["udp.source_port=1"]},
            {"assign": ["udp.destination_port=5353"]},
            {"filter": "last", "assign": ["ipv4.ttl=9"]}
        ]
    }))
    .unwrap()
    .try_map_filters(|filter| Ok::<_, ()>(filter != "skipped"))
    .unwrap();
    let frame = udp_frame(64);
    let dissector = Dissector::new(builtin::registry());
    let mut applied = Vec::new();
    let rewritten = rules
        .apply(
            &frame,
            &dissector,
            RewriteLimits::default(),
            |selected| Ok(*selected),
            |index, changes| {
                applied.push((
                    index,
                    changes
                        .into_iter()
                        .map(|change| (change.field, change.old, change.new))
                        .filter(|(field, ..)| !field.ends_with("checksum"))
                        .collect::<Vec<_>>(),
                ));
            },
        )
        .unwrap();
    assert_eq!(
        applied,
        [
            (0, vec![("ipv4#1.ttl".to_owned(), 64, 63)]),
            (2, vec![("udp#1.destination_port".to_owned(), 40001, 5353)]),
            (3, vec![("ipv4#1.ttl".to_owned(), 63, 9)]),
        ]
    );
    let decoded = dissector.decode(rewritten, Default::default()).unwrap();
    assert_eq!(decoded.packet.get::<Ipv4>().unwrap().ttl, 9);
    assert_eq!(decoded.packet.get::<Udp>().unwrap().destination_port, 5353);
}

#[test]
fn a_failed_rule_stops_before_later_filters_are_asked() {
    let rules = parse_json(json!({
        "schema": "packetcraftr.rewrite/v2",
        "rules": [
            {"filter": "a", "assign": ["tcp.sequence=1"]},
            {"filter": "b", "assign": ["ipv4.ttl=1"]}
        ]
    }))
    .unwrap();
    let mut asked = Vec::new();
    let error = rules
        .apply(
            &udp_frame(64),
            &Dissector::new(builtin::registry()),
            RewriteLimits::default(),
            |filter: &String| -> Result<bool, BoundaryError> {
                asked.push(filter.clone());
                Ok(true)
            },
            |_, _| panic!("no rule applies"),
        )
        .expect_err("the frame has no TCP layer");
    assert_eq!(error.classification().code, "packet.transform_unsupported");
    assert_eq!(asked, ["a"]);
}
