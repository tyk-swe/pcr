// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::{
    build::Builder,
    decode::Dissector,
    error::{BoundaryError, Classified},
    frame::{Frame, LinkType},
    layer::Raw,
    packet::Packet,
    protocol::{builtin, network::Ipv4, transport::Udp},
    transform::{
        ChecksumMode, RewriteLimits,
        rules::{self, Rules},
    },
};
use serde_json::json;
use std::time::UNIX_EPOCH;

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

#[test]
fn oversize_document_reject_before_read() {
    let document = vec![b' '; rules::MAX_REWRITE_DOCUMENT_BYTES + 1];
    assert!(matches!(
        parse(&document),
        Err(rules::Error::DocumentSize { actual, limit })
            if actual == limit + 1
    ));
}

#[test]
fn failed_rule_stops_before_filters_asked() {
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
