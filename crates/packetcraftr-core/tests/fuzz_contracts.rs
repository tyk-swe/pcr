// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::str::FromStr;
use std::time::Duration;

use packetcraftr_core::error::{Classified, Kind};
use packetcraftr_core::fuzz;

#[test]
fn fuzz_requests_stop_on_duplicate_strategies_and_case_overflow() {
    let mut request = fuzz::Request {
        cases: 2,
        strategies: vec![fuzz::Strategy::Boundary, fuzz::Strategy::Boundary],
        ..fuzz::Request::default()
    };
    assert!(matches!(
        request.validate(),
        Err(fuzz::Error::InvalidStrategies)
    ));

    request.strategies = vec![fuzz::Strategy::Boundary];
    request.first_case = u64::MAX;
    assert!(matches!(
        request.validate(),
        Err(fuzz::Error::CaseIndexOverflow)
    ));
}

#[test]
fn fuzz_targets_have_an_unambiguous_layer_field_grammar() {
    let target = fuzz::Target::from_str("3.destination_port").expect("target must parse");
    assert_eq!(target.layer, 3);
    assert_eq!(target.field, "destination_port");
    assert!(fuzz::Target::from_str("3.bad-field").is_err());
    assert!(fuzz::Target::from_str("destination_port").is_err());
}

#[test]
fn fuzz_failures_retain_stable_boundary_classifications() {
    let cases = [
        (fuzz::Error::InvalidStrategies, "cli.fuzz_limit", Kind::Cli),
        (
            fuzz::Error::InvalidBasePacket {
                message: "bad base".to_owned(),
            },
            "packet.fuzz_recipe",
            Kind::Packet,
        ),
        (
            fuzz::Error::NoCompatibleTargets,
            "packet.fuzz_target",
            Kind::Packet,
        ),
        (
            fuzz::Error::ByteLimit {
                actual: 11,
                limit: 10,
            },
            "policy.fuzz_resource_limit",
            Kind::Policy,
        ),
        (
            fuzz::Error::DurationLimit {
                actual: Duration::from_secs(11),
                limit: Duration::from_secs(10),
            },
            "policy.fuzz_resource_limit",
            Kind::Policy,
        ),
    ];

    for (error, code, kind) in cases {
        let classification = error.classification();
        assert_eq!(classification.code, code);
        assert_eq!(classification.kind, kind);
        assert!(classification.remediation.is_some());
        assert!(error.causes().is_empty());
        assert!(!error.to_string().is_empty());
    }
}

#[test]
fn a_campaign_publishes_the_duration_it_charged_against_its_own_deadline() {
    let request = fuzz::Request {
        seed: 5,
        cases: 8,
        strategies: vec![fuzz::Strategy::BitFlip],
        ..fuzz::Request::default()
    };
    let mut packet = packetcraftr_core::Packet::new();
    packet.push(packetcraftr_core::layer::Raw::new(b"elapsed".to_vec()));

    let report = fuzz::run(
        &request,
        packet,
        packetcraftr_core::protocol::builtin::registry(),
    )
    .expect("bounded offline campaign");

    assert_eq!(report.stats.cases_generated, 8);
    assert!(
        report.stats.elapsed > Duration::ZERO,
        "a generated campaign reports the time it took, not zero: {:?}",
        report.stats.elapsed
    );
    assert!(
        report.stats.elapsed < request.limits.max_duration,
        "{:?}",
        report.stats.elapsed
    );
}

#[test]
fn campaign_limits_reject_values_above_the_ceilings_they_enforce() {
    for limits in [
        fuzz::Limits {
            max_total_bytes: fuzz::MAX_TOTAL_BYTES + 1,
            ..fuzz::Limits::default()
        },
        fuzz::Limits {
            max_packet_bytes: fuzz::MAX_PACKET_BYTES + 1,
            ..fuzz::Limits::default()
        },
    ] {
        assert!(matches!(
            limits.validate(),
            Err(fuzz::Error::InvalidLimit { .. })
        ));
    }
    assert!(fuzz::Limits::default().validate().is_ok());
    const {
        assert!(fuzz::MAX_VALUE_NESTING <= packetcraftr_core::document::MAX_DOCUMENT_NESTING);
    }
}
