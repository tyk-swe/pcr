// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::str::FromStr;

use packetcraftr_workflow::{dns, fuzz};

#[test]
fn dns_names_and_response_codes_are_canonical_and_bounded() {
    assert_eq!(
        dns::canonical_query_name("WWW.Example.COM").expect("name must be valid"),
        "www.example.com."
    );
    assert_eq!(
        dns::canonical_query_name(".").expect("root must be valid"),
        "."
    );
    assert!(dns::canonical_query_name("bad..name").is_err());
    assert_eq!(dns::response_code_name(3), "name_error");
    assert_eq!(dns::response_code_name(u16::MAX), "unknown");
}

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
