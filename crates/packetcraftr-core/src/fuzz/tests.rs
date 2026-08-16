// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::protocol::{builtin::registry as default_registry, network::Ipv4, transport::Udp};
use crate::{
    Packet,
    build::{BuildMode, BuildOptions},
    layer::Raw,
    registry::ProtocolRegistry,
};
use bytes::Bytes;

use super::error::FuzzError;
use super::request::{FuzzLimits, FuzzRequest, FuzzStrategy};
use super::result::FuzzCaseOutcome;
use super::run::run as fuzz;

fn fuzz_protocol_registry() -> Arc<ProtocolRegistry> {
    Arc::new(default_registry().expect("built-in protocol registry"))
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
fn fuzz_same_seed_and_configuration_produce_identical_cases_and_bytes() {
    let request = FuzzRequest {
        seed: 0x1234_5678,
        cases: 32,
        ..FuzzRequest::default()
    };
    let first = fuzz(&request, udp_fuzz_packet(), fuzz_protocol_registry()).unwrap();
    let second = fuzz(&request, udp_fuzz_packet(), fuzz_protocol_registry()).unwrap();
    assert_eq!(first.cases.len(), second.cases.len());
    for (left, right) in first.cases.iter().zip(&second.cases) {
        assert_eq!(left.index, right.index);
        assert_eq!(left.seed, right.seed);
        assert_eq!(left.mutation, right.mutation);
        assert_eq!(left.shrink_values, right.shrink_values);
        assert_eq!(left.outcome, right.outcome);
        assert_eq!(
            left.built.as_ref().map(|built| built.bytes.clone()),
            right.built.as_ref().map(|built| built.bytes.clone())
        );
    }
}

#[test]
fn fuzz_bounded_resource_rejection_precedes_unbounded_case_growth() {
    let error = fuzz(
        &FuzzRequest {
            cases: 2,
            strategies: vec![FuzzStrategy::BitFlip],
            targets: vec!["2.bytes".parse().unwrap()],
            build: BuildOptions {
                max_packet_size: 64,
                ..BuildOptions::default()
            },
            limits: FuzzLimits {
                max_cases: 2,
                max_packet_bytes: 64,
                max_total_bytes: 64,
                max_field_bytes: 32,
                ..FuzzLimits::default()
            },
            ..FuzzRequest::default()
        },
        udp_fuzz_packet(),
        fuzz_protocol_registry(),
    )
    .unwrap_err();
    assert!(matches!(error, FuzzError::ByteLimit { .. }));
}

#[test]
fn fuzz_malformed_derived_fields_are_strictly_rejected_and_permissively_built() {
    let base = udp_fuzz_packet();
    let strict = fuzz(
        &FuzzRequest {
            seed: 1,
            cases: 8,
            strategies: vec![FuzzStrategy::Malformed],
            targets: vec!["1.length".parse().unwrap()],
            ..FuzzRequest::default()
        },
        base.clone(),
        fuzz_protocol_registry(),
    )
    .unwrap();
    assert!(
        strict
            .cases
            .iter()
            .any(|case| case.outcome == FuzzCaseOutcome::Rejected)
    );

    let permissive = fuzz(
        &FuzzRequest {
            seed: 1,
            cases: 8,
            strategies: vec![FuzzStrategy::Malformed],
            targets: vec!["1.length".parse().unwrap()],
            build: BuildOptions {
                mode: BuildMode::Permissive,
                ..BuildOptions::default()
            },
            ..FuzzRequest::default()
        },
        base,
        fuzz_protocol_registry(),
    )
    .unwrap();
    assert!(permissive.cases.iter().any(|case| {
        case.built
            .as_ref()
            .is_some_and(|built| built.requires_live_opt_in)
    }));
}
