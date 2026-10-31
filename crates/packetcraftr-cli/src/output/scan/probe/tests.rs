// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use serde_json::{Value, json};

use packetcraftr::probe;
use packetcraftr::scan as library;

use super::Probe;

const ADDRESS_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
const ADDRESS_V6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

fn evidence(endpoint: probe::Endpoint, address: IpAddr) -> library::ProbeEvidence {
    library::ProbeEvidence {
        measurement: library::Measurement::NoReply(library::Coverage::Pending),
        sequence: 7,
        stage: library::Stage::Scan,
        address,
        scope: None,
        endpoint,
        tcp_scan: match endpoint {
            probe::Endpoint::TcpAck { .. } => Some(library::TcpScan::Ack),
            probe::Endpoint::Tcp { .. } => Some(library::TcpScan::Syn),
            _ => None,
        },
        sctp_scan: (endpoint.transport() == probe::Transport::Sctp)
            .then_some(library::SctpScan::Init),
        attempt: 1,
        status: probe::Status::Timeout,
        classification: library::Classification::Timeout,
        reply: None,
        responder: None,
        sent_at: SystemTime::UNIX_EPOCH,
        received_at: None,
        latency: None,
        response: None,
        reason: "no reply".to_owned(),
        application: None,
        tcp_window: None,
    }
}

fn serialized(endpoint: probe::Endpoint, address: IpAddr) -> Value {
    let probe = Probe::try_from(evidence(endpoint, address)).unwrap();
    serde_json::to_value(&probe).unwrap()
}

fn expected(extra: Value) -> Value {
    let mut base = json!({
        "measurement": {"kind": "no_reply", "coverage": "pending"},
        "sequence": 7,
        "stage": "scan",
        "attempt": 1,
        "status": "timeout",
        "classification": "timeout",
        "sent_at": {"unix_seconds": 0, "nanoseconds": 0},
        "reason": "no reply",
    });
    for (key, value) in extra.as_object().unwrap() {
        base[key] = value.clone();
    }
    base
}

#[test]
fn serialized_probe_record_follows_the_endpoint_variant() {
    let cases: [(probe::Endpoint, IpAddr, Value); 9] = [
        (
            probe::Endpoint::Tcp { port: 443 },
            ADDRESS_V4,
            json!({
                "protocol": "tcp",
                "destination": "10.0.0.1",
                "destination_port": 443,
                "tcp_scan": {"mode": "syn", "flags": 2},
            }),
        ),
        (
            probe::Endpoint::TcpAck { port: 80 },
            ADDRESS_V4,
            json!({
                "protocol": "tcp",
                "destination": "10.0.0.1",
                "destination_port": 80,
                "tcp_scan": {"mode": "ack", "flags": 16},
            }),
        ),
        (
            probe::Endpoint::Udp { port: 53 },
            ADDRESS_V4,
            json!({
                "protocol": "udp",
                "destination": "10.0.0.1",
                "destination_port": 53,
            }),
        ),
        (
            probe::Endpoint::Sctp { port: 80 },
            ADDRESS_V4,
            json!({
                "protocol": "sctp",
                "destination": "10.0.0.1",
                "destination_port": 80,
                "sctp_scan": {"mode": "init", "chunk_type": 1},
            }),
        ),
        (
            probe::Endpoint::Icmp,
            ADDRESS_V4,
            json!({
                "protocol": "icmpv4",
                "destination": "10.0.0.1",
            }),
        ),
        (
            probe::Endpoint::Icmp,
            ADDRESS_V6,
            json!({
                "protocol": "icmpv6",
                "destination": "::1",
            }),
        ),
        (
            probe::Endpoint::IcmpTimestamp,
            ADDRESS_V4,
            json!({
                "protocol": "icmpv4",
                "destination": "10.0.0.1",
                "icmp_request": "timestamp",
            }),
        ),
        (
            probe::Endpoint::IcmpNetmask,
            ADDRESS_V4,
            json!({
                "protocol": "icmpv4",
                "destination": "10.0.0.1",
                "icmp_request": "netmask",
            }),
        ),
        (
            probe::Endpoint::Ip { protocol: 47 },
            ADDRESS_V4,
            json!({
                "protocol": "ip",
                "destination": "10.0.0.1",
                "ip_protocol": 47,
            }),
        ),
    ];
    for (endpoint, address, extra) in cases {
        assert_eq!(
            serialized(endpoint, address),
            expected(extra),
            "endpoint {endpoint:?} at {address}"
        );
    }
}
