// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::Bytes;
use packetcraftr_core::build::Options;
use packetcraftr_core::codec::Mode;
use packetcraftr_core::error::Classified;
use packetcraftr_core::fuzz::{CaseOutcome, Error, Limits, Request, Strategy, run as fuzz};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::Udp;
use packetcraftr_core::registry::Registry;

fn fuzz_protocol_registry() -> Arc<Registry> {
    packetcraftr_core::protocol::builtin::registry()
}

fn udp_fuzz_packet() -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(192, 0, 2, 2),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 40_000,
            destination_port: 9,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::from_static(b"abcdef")));
    packet
}

#[test]
fn fuzz_bounded_resource_rejection_precedes_unbounded_case_growth() {
    let error = fuzz(
        &Request {
            cases: 2,
            strategies: vec![Strategy::BitFlip],
            targets: vec!["2.bytes".parse().unwrap()],
            build: Options {
                limits: packetcraftr_core::packet::Limits {
                    max_packet_size: 64,
                    ..packetcraftr_core::packet::Limits::default()
                },
                ..Options::default()
            },
            limits: Limits {
                max_cases: 2,
                max_packet_bytes: 64,
                max_total_bytes: 64,
                max_field_bytes: 32,
                ..Limits::default()
            },
            ..Request::default()
        },
        udp_fuzz_packet(),
        fuzz_protocol_registry(),
    )
    .unwrap_err();
    // The base packet's own reflected values exhaust the 64-byte campaign budget.
    assert!(
        matches!(error, Error::ValueTooLarge { limit: 64 }),
        "{error:?}"
    );
    assert_eq!(
        error.classification().code,
        "policy.fuzz_resource_limit",
        "{error:?}"
    );
}

#[test]
fn fuzz_malformed_derived_fields_are_strictly_rejected_and_permissively_built() {
    let base = udp_fuzz_packet();
    let strict = fuzz(
        &Request {
            seed: 1,
            cases: 8,
            strategies: vec![Strategy::Malformed],
            targets: vec!["1.length".parse().unwrap()],
            ..Request::default()
        },
        base.clone(),
        fuzz_protocol_registry(),
    )
    .unwrap();
    assert!(
        strict
            .cases
            .iter()
            .any(|case| case.outcome == CaseOutcome::Rejected)
    );

    let permissive = fuzz(
        &Request {
            seed: 1,
            cases: 8,
            strategies: vec![Strategy::Malformed],
            targets: vec!["1.length".parse().unwrap()],
            build: Options {
                mode: Mode::Permissive,
                ..Options::default()
            },
            ..Request::default()
        },
        base,
        fuzz_protocol_registry(),
    )
    .unwrap();
    assert!(permissive.cases.iter().any(|case| {
        case.built
            .as_ref()
            .is_some_and(|built| built.mode == Mode::Permissive)
    }));
}
