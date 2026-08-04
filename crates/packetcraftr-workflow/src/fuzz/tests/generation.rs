// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{Ipv4Addr, Ipv6Addr};

use super::super::MAX_FUZZ_STRATEGIES;
use super::super::engine::fuzz;
use super::super::error::FuzzError;
use super::super::execution::SplitMix64;
use super::super::model::{FuzzCaseOutcome, FuzzLimits, FuzzRequest, FuzzStrategy};
use super::super::mutation::{bounded_value_size, random_value};
use super::{fuzz_protocol_registry, udp_fuzz_packet};
use bytes::Bytes;
use packetcraftr_core::error::{Classified, Kind};
use packetcraftr_packet::{
    Packet,
    build::{BuildMode, BuildOptions},
    field::{FieldKind, FieldValue},
    layer::Raw,
};

#[test]
fn random_value_supports_every_reflective_scalar_kind_within_bounds() {
    let limits = FuzzLimits {
        max_field_bytes: 8,
        max_list_items: 2,
        ..FuzzLimits::default()
    };
    let cases = [
        (FieldKind::Bool, FieldValue::Bool(false)),
        (FieldKind::Unsigned, FieldValue::Unsigned(0)),
        (FieldKind::Signed, FieldValue::Signed(0)),
        (FieldKind::Text, FieldValue::Text(String::new())),
        (FieldKind::Bytes, FieldValue::Bytes(Bytes::new())),
        (FieldKind::Ipv4, FieldValue::Ipv4(Ipv4Addr::UNSPECIFIED)),
        (FieldKind::Ipv6, FieldValue::Ipv6(Ipv6Addr::UNSPECIFIED)),
        (FieldKind::Mac, FieldValue::Mac([0; 6])),
    ];
    for (kind, original) in cases {
        let mut random = SplitMix64::new(7);
        let value = random_value(kind, &original, &mut random, limits);
        assert!(matches!(
            (&value, kind),
            (FieldValue::Bool(_), FieldKind::Bool)
                | (FieldValue::Unsigned(_), FieldKind::Unsigned)
                | (FieldValue::Signed(_), FieldKind::Signed)
                | (FieldValue::Text(_), FieldKind::Text)
                | (FieldValue::Bytes(_), FieldKind::Bytes)
                | (FieldValue::Ipv4(_), FieldKind::Ipv4)
                | (FieldValue::Ipv6(_), FieldKind::Ipv6)
                | (FieldValue::Mac(_), FieldKind::Mac)
        ));
        assert!(
            bounded_value_size(
                &value,
                limits.max_field_bytes.max(16),
                limits.max_list_items,
                0
            )
            .is_some()
        );
    }
}

#[test]
fn fuzz_errors_report_case_sequences_only_for_case_scoped_failures() {
    let errors = [
        FuzzError::Clock {
            case_index: 4,
            message: "clock".to_owned(),
        },
        FuzzError::InvalidEvidence {
            case_index: 4,
            message: "evidence".to_owned(),
        },
        FuzzError::StatisticsOverflow { case_index: 4 },
    ];
    for error in errors {
        assert_eq!(error.sequence(), Some(4));
    }
    assert_eq!(FuzzError::CaseIndexOverflow.sequence(), None);
}

#[test]
fn fuzz_errors_use_stable_classification_families() {
    let cases = [
        (FuzzError::InvalidStrategies, "cli.fuzz_limit", Kind::Cli),
        (
            FuzzError::InvalidBasePacket {
                message: "bad".to_owned(),
            },
            "packet.fuzz_recipe",
            Kind::Packet,
        ),
        (
            FuzzError::NoCompatibleTargets,
            "packet.fuzz_target",
            Kind::Packet,
        ),
        (
            FuzzError::ByteLimit {
                actual: 2,
                limit: 1,
            },
            "policy.fuzz_resource_limit",
            Kind::Policy,
        ),
        (
            FuzzError::MalformedLiveOptInRequired,
            "policy.fuzz_malformed_opt_in",
            Kind::Policy,
        ),
        (
            FuzzError::Clock {
                case_index: 0,
                message: "bad".to_owned(),
            },
            "io.fuzz_clock",
            Kind::Io,
        ),
        (
            FuzzError::StatisticsOverflow { case_index: 0 },
            "internal.fuzz_evidence",
            Kind::Internal,
        ),
    ];
    for (error, code, kind) in cases {
        assert_eq!(error.classification().code, code, "{error}");
        assert_eq!(error.classification().kind, kind, "{error}");
    }
}

#[test]
fn same_seed_and_configuration_produce_identical_cases_and_bytes() {
    let request = FuzzRequest {
        seed: 0x1234_5678,
        cases: 128,
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
            left.built.as_ref().map(|value| value.bytes.clone()),
            right.built.as_ref().map(|value| value.bytes.clone())
        );
    }
}

#[test]
fn first_case_reproduces_one_case_without_replaying_predecessors() {
    let request = FuzzRequest {
        seed: 42,
        cases: 32,
        strategies: vec![FuzzStrategy::Random],
        ..FuzzRequest::default()
    };
    let campaign = fuzz(&request, udp_fuzz_packet(), fuzz_protocol_registry()).unwrap();
    let expected = &campaign.cases[19];
    let reproduced = fuzz(
        &FuzzRequest {
            first_case: expected.index,
            cases: 1,
            ..request
        },
        udp_fuzz_packet(),
        fuzz_protocol_registry(),
    )
    .unwrap();
    let actual = &reproduced.cases[0];
    assert_eq!(actual.reproduction, expected.reproduction);
    assert_eq!(actual.mutation, expected.mutation);
    assert_eq!(
        actual.built.as_ref().map(|value| &value.bytes),
        expected.built.as_ref().map(|value| &value.bytes)
    );
}

#[test]
fn case_range_accepts_the_largest_single_index_without_off_by_one_overflow() {
    let request = FuzzRequest {
        first_case: u64::MAX,
        cases: 1,
        ..FuzzRequest::default()
    };
    assert!(request.validate().is_ok());

    let request = FuzzRequest {
        first_case: u64::MAX,
        cases: 2,
        ..FuzzRequest::default()
    };
    assert!(matches!(
        request.validate(),
        Err(FuzzError::CaseIndexOverflow)
    ));
}

#[test]
fn shrink_data_is_finite_deterministic_and_strictly_simpler() {
    let result = fuzz(
        &FuzzRequest {
            seed: 7,
            cases: 8,
            strategies: vec![FuzzStrategy::BitFlip],
            targets: vec!["2.bytes".parse().unwrap()],
            limits: FuzzLimits {
                max_shrink_steps: 2,
                ..FuzzLimits::default()
            },
            ..FuzzRequest::default()
        },
        udp_fuzz_packet(),
        fuzz_protocol_registry(),
    )
    .unwrap();
    for case in result.cases {
        assert!(!case.shrink_values.is_empty());
        assert!(case.shrink_values.len() <= 2);
        assert!(!case.shrink_values.contains(&case.mutation.value));
    }
}

#[test]
fn random_list_mutation_never_clones_beyond_field_or_item_bounds() {
    let limits = FuzzLimits {
        max_field_bytes: 8,
        max_list_items: 2,
        ..FuzzLimits::default()
    };
    let original = FieldValue::List(vec![
        FieldValue::Text("x".repeat(1024)),
        FieldValue::Unsigned(1),
        FieldValue::Unsigned(2),
    ]);
    for seed in 0..128 {
        let mut random = SplitMix64::new(seed);
        let value = random_value(FieldKind::List, &original, &mut random, limits);
        let FieldValue::List(values) = value else {
            panic!("list strategy must produce a list");
        };
        assert!(values.len() <= 2);
        assert!(
            bounded_value_size(
                &FieldValue::List(values),
                limits.max_field_bytes,
                limits.max_list_items,
                0,
            )
            .is_some()
        );
    }
}

#[test]
fn nested_empty_lists_are_charged_to_the_structural_byte_budget() {
    let nested = FieldValue::List(vec![
        FieldValue::List(vec![FieldValue::List(Vec::new()); 4]);
        4
    ]);
    assert!(bounded_value_size(&nested, 8, 4, 0).is_none());
    assert!(bounded_value_size(&nested, 32, 4, 0).is_some());
}

#[test]
fn limits_reject_before_unbounded_case_or_byte_growth() {
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
                max_evidence_bytes: 64,
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
fn rejected_case_recipes_and_shrink_data_share_the_aggregate_byte_budget() {
    let error = fuzz(
        &FuzzRequest {
            cases: 100,
            strategies: vec![FuzzStrategy::Boundary],
            targets: vec!["2.bytes".parse().unwrap()],
            build: BuildOptions {
                max_packet_size: 64,
                ..BuildOptions::default()
            },
            limits: FuzzLimits {
                max_cases: 100,
                max_packet_bytes: 64,
                max_total_bytes: 4_096,
                max_field_bytes: 1_024,
                max_evidence_bytes: 4_096,
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
fn oversized_base_packet_is_rejected_before_case_cloning() {
    let mut oversized = Packet::new();
    for _ in 0..=BuildOptions::default().max_layers {
        oversized.push(Raw::new(Bytes::new()));
    }
    let error = fuzz(&FuzzRequest::default(), oversized, fuzz_protocol_registry()).unwrap_err();
    assert!(matches!(error, FuzzError::InvalidBasePacket { .. }));
}

#[test]
fn strategy_expansion_is_hard_bounded() {
    let request = FuzzRequest {
        strategies: vec![FuzzStrategy::Boundary; MAX_FUZZ_STRATEGIES + 1],
        ..FuzzRequest::default()
    };
    let error = request.validate().unwrap_err();
    assert!(matches!(
        error,
        FuzzError::InvalidLimit {
            field: "strategies",
            ..
        }
    ));
}

#[test]
fn malformed_derived_fields_are_rejected_strictly_and_built_permissively() {
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
