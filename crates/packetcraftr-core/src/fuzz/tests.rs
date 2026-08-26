// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::protocol::{network::Ipv4, transport::Udp};
use crate::{
    Packet,
    build::{Mode, Options},
    layer::Raw,
    registry::Registry,
};
use bytes::Bytes;

use super::error::Error;
use super::request::{Limits, Request, Strategy};
use super::result::CaseOutcome;
use super::run::run as fuzz;
use super::run::run_with_events;
use crate::error::{BoundaryError, Classification, Kind};

fn fuzz_protocol_registry() -> Arc<Registry> {
    Arc::new(crate::protocol::builtin::registry().expect("built-in protocol registry"))
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

fn raw_fuzz_packet() -> Packet {
    let mut packet = Packet::new();
    packet.push(Raw::new(Bytes::from_static(b"abcd")));
    packet
}

fn output_failure() -> BoundaryError {
    BoundaryError::new(
        "induced fuzz output failure",
        Classification::new("io.test_output", Kind::Io, None),
        Vec::new(),
    )
}

#[test]
fn fuzz_same_seed_and_configuration_produce_identical_cases_and_bytes() {
    let request = Request {
        seed: 0x1234_5678,
        cases: 32,
        ..Request::default()
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
fn aggregate_fuzz_validates_case_count_before_collecting() {
    let error = fuzz(
        &Request {
            cases: usize::MAX,
            ..Request::default()
        },
        raw_fuzz_packet(),
        fuzz_protocol_registry(),
    )
    .expect_err("an oversized aggregate campaign must fail validation");

    assert!(matches!(error, Error::InvalidLimit { field: "cases", .. }));
}

#[test]
fn fuzz_bounded_resource_rejection_precedes_unbounded_case_growth() {
    let error = fuzz(
        &Request {
            cases: 2,
            strategies: vec![Strategy::BitFlip],
            targets: vec!["2.bytes".parse().unwrap()],
            build: Options {
                max_packet_size: 64,
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
    assert!(matches!(error, Error::ByteLimit { .. }));
}

#[test]
fn offline_fuzz_sink_failure_stops_generation_after_the_emitted_case() {
    let request = Request {
        cases: 3,
        strategies: vec![Strategy::BitFlip],
        targets: vec!["0.bytes".parse().unwrap()],
        ..Request::default()
    };
    let emitted = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = std::sync::Arc::clone(&emitted);

    let error = run_with_events(
        &request,
        raw_fuzz_packet(),
        fuzz_protocol_registry(),
        move |case| {
            observed.lock().unwrap().push(case.index);
            Err(output_failure())
        },
    )
    .expect_err("the first sink write must stop generation");

    assert!(matches!(error, Error::Output { .. }));
    assert_eq!(*emitted.lock().unwrap(), [0]);
}

#[test]
fn offline_fuzz_late_limit_failure_preserves_earlier_cases() {
    let request = Request {
        cases: 3,
        strategies: vec![Strategy::BitFlip],
        targets: vec!["0.bytes".parse().unwrap()],
        build: Options {
            max_packet_size: 32,
            ..Options::default()
        },
        limits: Limits {
            max_cases: 3,
            max_packet_bytes: 32,
            max_total_bytes: 60,
            max_field_bytes: 16,
            ..Limits::default()
        },
        ..Request::default()
    };
    let emitted = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = std::sync::Arc::clone(&emitted);

    let error = run_with_events(
        &request,
        raw_fuzz_packet(),
        fuzz_protocol_registry(),
        move |case| {
            observed.lock().unwrap().push(case.index);
            Ok(())
        },
    )
    .expect_err("the third retained case must exceed the campaign limit");

    assert!(matches!(error, Error::ByteLimit { .. }));
    assert_eq!(*emitted.lock().unwrap(), [0, 1]);
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
            .is_some_and(|built| built.requires_live_opt_in)
    }));
}
