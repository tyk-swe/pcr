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
