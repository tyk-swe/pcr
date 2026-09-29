// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::Bytes;
use packetcraftr_core::build::Options;
use packetcraftr_core::codec::Mode;
use packetcraftr_core::error::{BoundaryError, Classification, Classified, Kind};
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::fuzz::{
    CaseOutcome, Error, Limits, Request, Strategy, run as fuzz, run_observed,
};
use packetcraftr_core::layer::{Malformed, Raw};
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
fn fuzz_base_packet_values_above_max_list_items_name_that_limit() {
    let registry = fuzz_protocol_registry();
    let packet = packetcraftr_core::expression::parse(
        r#"ipv4()/udp(destination_port=53)/dns(questions=[{name="example.test.",type=1,class=1}])"#,
        &registry,
        Default::default(),
    )
    .expect("recipe parses");
    let error = fuzz(
        &Request {
            cases: 1,
            limits: Limits {
                max_list_items: 1,
                ..Limits::default()
            },
            ..Request::default()
        },
        packet,
        registry,
    )
    .expect_err("a question object has more than one member");

    assert!(
        matches!(error, Error::ValueItems { items: 3, limit: 1 }),
        "{error:?}"
    );
    assert!(error.to_string().contains("max_list_items=1"), "{error}");
    let classification = error.classification();
    assert_eq!(classification.code, "policy.fuzz_resource_limit");
    assert_eq!(classification.kind, Kind::Policy);
}

#[test]
fn fuzz_boundary_text_mutations_respect_the_field_byte_limit() {
    let mut packet = Packet::new();
    packet.push(Malformed::new(None, Bytes::from_static(b"abcd"), "fixture"));
    let report = fuzz(
        &Request {
            cases: 32,
            strategies: vec![Strategy::Boundary],
            targets: vec!["0.reason".parse().unwrap()],
            limits: Limits {
                max_field_bytes: 8,
                ..Limits::default()
            },
            ..Request::default()
        },
        packet,
        fuzz_protocol_registry(),
    )
    .unwrap();

    assert_eq!(report.cases.len(), 32);
    for case in &report.cases {
        let FieldValue::Text(text) = &case.mutation.value else {
            panic!(
                "case {} did not mutate text: {:?}",
                case.index, case.mutation
            );
        };
        assert!(text.len() <= 8, "case {}: {text:?}", case.index);
    }
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

    let error = run_observed(
        &request,
        raw_fuzz_packet(),
        fuzz_protocol_registry(),
        move |case, _| {
            observed.lock().unwrap().push(case.index);
            Err(Error::Output {
                source: output_failure(),
            })
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
            limits: packetcraftr_core::packet::Limits {
                max_packet_size: 32,
                ..packetcraftr_core::packet::Limits::default()
            },
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

    let error = run_observed(
        &request,
        raw_fuzz_packet(),
        fuzz_protocol_registry(),
        move |case, _| {
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
            .is_some_and(|built| built.mode == Mode::Permissive)
    }));
}
