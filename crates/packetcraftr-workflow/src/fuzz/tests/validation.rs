// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use super::super::error::FuzzError;
use super::super::model::{FuzzLimits, FuzzLiveOptions, FuzzRequest, FuzzStrategy, FuzzTarget};
use super::super::{
    MAX_FUZZ_CASES, MAX_FUZZ_DURATION, MAX_FUZZ_FIELD_BYTES, MAX_FUZZ_LIST_ITEMS, MAX_FUZZ_RATE,
    MAX_FUZZ_SHRINK_STEPS, MAX_FUZZ_STRATEGIES,
};

#[test]
fn fuzz_strategy_names_and_display_are_stable() {
    for (strategy, expected) in [
        (FuzzStrategy::Boundary, "boundary"),
        (FuzzStrategy::Random, "random"),
        (FuzzStrategy::BitFlip, "bit_flip"),
        (FuzzStrategy::Malformed, "malformed"),
    ] {
        assert_eq!(strategy.as_str(), expected);
        assert_eq!(strategy.to_string(), expected);
    }
    assert_eq!(FuzzStrategy::default(), FuzzStrategy::Boundary);
}

#[test]
fn fuzz_target_parser_accepts_canonical_layer_and_field_names() {
    let target: FuzzTarget = "12.source_port_2".parse().unwrap();
    assert_eq!(target.layer, 12);
    assert_eq!(target.field, "source_port_2");
    assert_eq!(target.to_string(), "12.source_port_2");
}

#[test]
fn fuzz_target_parser_rejects_missing_or_ambiguous_components() {
    for value in [
        "",
        "1",
        ".field",
        "layer.field",
        "1.",
        "1.bad-name",
        "1.white space",
        "1.field.more",
    ] {
        let error = value.parse::<FuzzTarget>().unwrap_err();
        assert!(
            error.to_string().contains("expected LAYER.FIELD"),
            "{value}"
        );
    }
}

#[test]
fn fuzz_limits_reject_each_zero_sized_resource() {
    for field in [
        "max_cases",
        "max_packet_bytes",
        "max_total_bytes",
        "max_field_bytes",
        "max_list_items",
        "max_shrink_steps",
        "max_evidence_frames",
        "max_evidence_bytes",
    ] {
        let mut limits = FuzzLimits::default();
        match field {
            "max_cases" => limits.max_cases = 0,
            "max_packet_bytes" => limits.max_packet_bytes = 0,
            "max_total_bytes" => limits.max_total_bytes = 0,
            "max_field_bytes" => limits.max_field_bytes = 0,
            "max_list_items" => limits.max_list_items = 0,
            "max_shrink_steps" => limits.max_shrink_steps = 0,
            "max_evidence_frames" => limits.max_evidence_frames = 0,
            "max_evidence_bytes" => limits.max_evidence_bytes = 0,
            _ => unreachable!(),
        }
        assert!(matches!(
            limits.validate(),
            Err(FuzzError::InvalidLimit {
                field: actual,
                value: 0,
                ..
            }) if actual == field
        ));
    }
}

#[test]
fn fuzz_limits_reject_each_value_above_its_hard_maximum() {
    let cases = [
        (
            "max_cases",
            FuzzLimits {
                max_cases: MAX_FUZZ_CASES + 1,
                ..FuzzLimits::default()
            },
        ),
        (
            "max_field_bytes",
            FuzzLimits {
                max_field_bytes: MAX_FUZZ_FIELD_BYTES + 1,
                ..FuzzLimits::default()
            },
        ),
        (
            "max_list_items",
            FuzzLimits {
                max_list_items: MAX_FUZZ_LIST_ITEMS + 1,
                ..FuzzLimits::default()
            },
        ),
        (
            "max_shrink_steps",
            FuzzLimits {
                max_shrink_steps: MAX_FUZZ_SHRINK_STEPS + 1,
                ..FuzzLimits::default()
            },
        ),
    ];
    for (field, limits) in cases {
        assert!(matches!(
            limits.validate(),
            Err(FuzzError::InvalidLimit { field: actual, .. }) if actual == field
        ));
    }
}

#[test]
fn fuzz_limits_reject_inconsistent_packet_and_evidence_budgets() {
    let error = FuzzLimits {
        max_packet_bytes: 2,
        max_total_bytes: 1,
        max_evidence_bytes: 1,
        ..FuzzLimits::default()
    }
    .validate()
    .unwrap_err();
    assert!(matches!(
        error,
        FuzzError::InvalidLimit {
            field: "max_packet_bytes",
            ..
        }
    ));

    let error = FuzzLimits {
        max_packet_bytes: 1,
        max_total_bytes: 1,
        max_evidence_bytes: 2,
        ..FuzzLimits::default()
    }
    .validate()
    .unwrap_err();
    assert!(matches!(
        error,
        FuzzError::InvalidLimit {
            field: "max_evidence_bytes",
            ..
        }
    ));
}

#[test]
fn fuzz_limits_reject_zero_and_excessive_duration() {
    for duration in [
        Duration::ZERO,
        MAX_FUZZ_DURATION.saturating_add(Duration::from_nanos(1)),
    ] {
        assert!(matches!(
            FuzzLimits {
                max_duration: duration,
                ..FuzzLimits::default()
            }
            .validate(),
            Err(FuzzError::InvalidDuration { value, .. }) if value == duration
        ));
    }
}

#[test]
fn fuzz_request_rejects_empty_duplicate_or_excessive_strategy_sets() {
    assert!(matches!(
        FuzzRequest {
            strategies: vec![FuzzStrategy::Boundary, FuzzStrategy::Boundary],
            ..FuzzRequest::default()
        }
        .validate(),
        Err(FuzzError::InvalidStrategies)
    ));
    assert!(matches!(
        FuzzRequest {
            strategies: Vec::new(),
            ..FuzzRequest::default()
        }
        .validate(),
        Err(FuzzError::InvalidStrategies)
    ));
    assert!(matches!(
        FuzzRequest {
            strategies: vec![FuzzStrategy::Boundary; MAX_FUZZ_STRATEGIES + 1],
            ..FuzzRequest::default()
        }
        .validate(),
        Err(FuzzError::InvalidLimit {
            field: "strategies",
            ..
        })
    ));
}

#[test]
fn fuzz_request_rejects_invalid_build_packet_size() {
    for size in [0, FuzzLimits::default().max_packet_bytes + 1] {
        let mut request = FuzzRequest::default();
        request.build.max_packet_size = size;
        assert!(matches!(
            request.validate(),
            Err(FuzzError::InvalidLimit {
                field: "build.max_packet_size",
                ..
            })
        ));
    }
}

#[test]
fn fuzz_live_options_validate_timeout_and_rate_bounds() {
    assert!(FuzzLiveOptions::default().validate().is_ok());
    for timeout in [
        Duration::ZERO,
        packetcraftr_net::capture::MAX_TIMEOUT.saturating_add(Duration::from_nanos(1)),
    ] {
        assert!(matches!(
            FuzzLiveOptions {
                timeout,
                ..FuzzLiveOptions::default()
            }
            .validate(),
            Err(FuzzError::InvalidTimeout { value, .. }) if value == timeout
        ));
    }
    for rate in [0, MAX_FUZZ_RATE + 1] {
        assert!(matches!(
            FuzzLiveOptions {
                cases_per_second: Some(rate),
                ..FuzzLiveOptions::default()
            }
            .validate(),
            Err(FuzzError::InvalidLimit {
                field: "cases_per_second",
                ..
            })
        ));
    }
}
