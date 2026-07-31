// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;

use super::execution::SplitMix64;
use super::mutation::{bounded_value_size, random_value};
use super::*;
use crate::{BoundaryError, Stats};
use packetcraftr_packet::{
    build::BuildMode, document::PacketDocument, field::WireValue, layer::Raw,
};
use packetcraftr_protocol::{builtin::registry as default_registry, network::Ipv4, transport::Udp};
use std::result::Result;

fn fuzz_protocol_registry() -> Arc<ProtocolRegistry> {
    Arc::new(default_registry().unwrap())
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

#[derive(Default)]
struct RecordingAuthorizer {
    calls: usize,
    deny: bool,
}

impl FuzzAuthorizer for RecordingAuthorizer {
    fn authorize_operation(
        &mut self,
        packets: &[Packet],
        _destination: Option<IpAddr>,
        _maximum_wire_bytes: u64,
        _requires_malformed_live: bool,
    ) -> Result<(), BoundaryError> {
        self.calls += 1;
        assert!(!packets.is_empty());
        if self.deny {
            return Err(BoundaryError::new(
                "denied",
                Classification::new("policy.test", Kind::Policy, None),
                Vec::new(),
            ));
        }
        Ok(())
    }
}

#[derive(Default)]
struct RecordingExecutor {
    calls: usize,
    response: Option<Vec<u8>>,
    response_delay: Duration,
    invalid_statistics: bool,
    sleep: Option<Duration>,
}

impl FuzzExecutor for RecordingExecutor {
    fn execute(
        &mut self,
        case: &FuzzExecutionCase,
        _timeout: Duration,
    ) -> Result<FuzzCaseExecution, BoundaryError> {
        self.calls += 1;
        if let Some(delay) = self.sleep {
            std::thread::sleep(delay);
        }
        let built = Builder::new(fuzz_protocol_registry())
            .build(
                case.packet.clone(),
                BuildContext::default(),
                BuildOptions {
                    mode: BuildMode::Permissive,
                    ..BuildOptions::default()
                },
            )
            .map_err(|source| {
                BoundaryError::new(
                    source.to_string(),
                    Classification::new("packet.test", Kind::Packet, None),
                    Vec::new(),
                )
            })?;
        let sent = Frame::new(
            std::time::UNIX_EPOCH,
            LinkType::BSD_RAW,
            built.bytes.clone(),
        )
        .unwrap();
        let responses = self
            .response
            .as_ref()
            .map(|bytes| {
                vec![
                    Frame::new(
                        std::time::UNIX_EPOCH + self.response_delay,
                        LinkType::BSD_RAW,
                        bytes.clone(),
                    )
                    .unwrap(),
                ]
            })
            .unwrap_or_default();
        Ok(FuzzCaseExecution {
            stats: Stats {
                packets_attempted: 1,
                packets_completed: u64::from(!self.invalid_statistics),
                bytes: built.bytes.len() as u64,
                ..Stats::default()
            },
            built,
            sent,
            responses,
            unmatched: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
        })
    }
}

#[derive(Default)]
struct RecordingClock {
    delays: Vec<Duration>,
}

impl Clock for RecordingClock {
    type Error = Infallible;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
        self.delays.push(delay);
        Ok(())
    }
}

#[test]
fn authorization_denial_precedes_every_live_execution() {
    let mut authorizer = RecordingAuthorizer {
        deny: true,
        ..RecordingAuthorizer::default()
    };
    let mut executor = RecordingExecutor::default();
    let mut clock = RecordingClock::default();
    let result = fuzz_live(
        &FuzzRequest {
            cases: 4,
            strategies: vec![FuzzStrategy::BitFlip],
            targets: vec!["2.bytes".parse().unwrap()],
            ..FuzzRequest::default()
        },
        FuzzLiveOptions::default(),
        udp_fuzz_packet(),
        fuzz_protocol_registry(),
        &mut authorizer,
        &mut executor,
        &mut clock,
    );
    assert!(matches!(result, Err(FuzzError::Authorization(_))));
    assert_eq!(authorizer.calls, 1);
    assert_eq!(executor.calls, 0);
    assert!(clock.delays.is_empty());
}

#[test]
fn malformed_call_site_opt_in_precedes_authorizer_and_executor() {
    let mut authorizer = RecordingAuthorizer::default();
    let mut executor = RecordingExecutor::default();
    let mut clock = RecordingClock::default();
    let result = fuzz_live(
        &FuzzRequest {
            cases: 1,
            strategies: vec![FuzzStrategy::Malformed],
            targets: vec!["1.length".parse().unwrap()],
            build: BuildOptions {
                mode: BuildMode::Permissive,
                ..BuildOptions::default()
            },
            ..FuzzRequest::default()
        },
        FuzzLiveOptions::default(),
        udp_fuzz_packet(),
        fuzz_protocol_registry(),
        &mut authorizer,
        &mut executor,
        &mut clock,
    );
    assert!(matches!(result, Err(FuzzError::MalformedLiveOptInRequired)));
    assert_eq!(authorizer.calls, 0);
    assert_eq!(executor.calls, 0);
}

#[test]
fn worst_case_duration_is_rejected_before_authorization_or_execution() {
    let mut authorizer = RecordingAuthorizer::default();
    let mut executor = RecordingExecutor::default();
    let mut clock = RecordingClock::default();
    let result = fuzz_live(
        &FuzzRequest {
            cases: 1,
            strategies: vec![FuzzStrategy::BitFlip],
            targets: vec!["2.bytes".parse().unwrap()],
            limits: FuzzLimits {
                max_duration: Duration::from_millis(1),
                ..FuzzLimits::default()
            },
            ..FuzzRequest::default()
        },
        FuzzLiveOptions {
            timeout: Duration::from_secs(1),
            ..FuzzLiveOptions::default()
        },
        udp_fuzz_packet(),
        fuzz_protocol_registry(),
        &mut authorizer,
        &mut executor,
        &mut clock,
    );
    assert!(matches!(result, Err(FuzzError::DurationLimit { .. })));
    assert_eq!(authorizer.calls, 0);
    assert_eq!(executor.calls, 0);
}

#[test]
fn actual_executor_wall_time_cannot_evade_the_duration_limit() {
    let mut authorizer = RecordingAuthorizer::default();
    let mut executor = RecordingExecutor {
        sleep: Some(Duration::from_millis(25)),
        ..RecordingExecutor::default()
    };
    let mut clock = RecordingClock::default();
    let result = fuzz_live(
        &FuzzRequest {
            cases: 1,
            strategies: vec![FuzzStrategy::BitFlip],
            targets: vec!["2.bytes".parse().unwrap()],
            limits: FuzzLimits {
                max_duration: Duration::from_millis(10),
                ..FuzzLimits::default()
            },
            ..FuzzRequest::default()
        },
        FuzzLiveOptions {
            timeout: Duration::from_millis(1),
            ..FuzzLiveOptions::default()
        },
        udp_fuzz_packet(),
        fuzz_protocol_registry(),
        &mut authorizer,
        &mut executor,
        &mut clock,
    );
    assert!(matches!(result, Err(FuzzError::DurationLimit { .. })));
    assert_eq!(authorizer.calls, 1);
    assert_eq!(executor.calls, 1);
}

#[test]
fn expired_executor_evidence_is_not_validated() {
    let mut authorizer = RecordingAuthorizer::default();
    let mut executor = RecordingExecutor {
        invalid_statistics: true,
        sleep: Some(Duration::from_millis(25)),
        ..RecordingExecutor::default()
    };
    let result = fuzz_live(
        &FuzzRequest {
            cases: 1,
            strategies: vec![FuzzStrategy::BitFlip],
            targets: vec!["2.bytes".parse().unwrap()],
            limits: FuzzLimits {
                max_duration: Duration::from_millis(10),
                ..FuzzLimits::default()
            },
            ..FuzzRequest::default()
        },
        FuzzLiveOptions {
            timeout: Duration::from_millis(1),
            ..FuzzLiveOptions::default()
        },
        udp_fuzz_packet(),
        fuzz_protocol_registry(),
        &mut authorizer,
        &mut executor,
        &mut RecordingClock::default(),
    );

    assert!(matches!(result, Err(FuzzError::DurationLimit { .. })));
    assert_eq!(authorizer.calls, 1);
    assert_eq!(executor.calls, 1);
}

#[test]
fn live_rate_and_timeout_are_bounded_before_execution() {
    let mut authorizer = RecordingAuthorizer::default();
    let mut executor = RecordingExecutor::default();
    let mut clock = RecordingClock::default();
    let result = fuzz_live(
        &FuzzRequest {
            cases: 3,
            strategies: vec![FuzzStrategy::BitFlip],
            targets: vec!["2.bytes".parse().unwrap()],
            build: BuildOptions {
                mode: BuildMode::Permissive,
                ..BuildOptions::default()
            },
            ..FuzzRequest::default()
        },
        FuzzLiveOptions {
            timeout: Duration::from_millis(10),
            cases_per_second: Some(100),
            destination: None,
            allow_malformed_live: true,
        },
        udp_fuzz_packet(),
        fuzz_protocol_registry(),
        &mut authorizer,
        &mut executor,
        &mut clock,
    )
    .unwrap();
    assert_eq!(result.mode, FuzzMode::Live);
    assert_eq!(executor.calls, 3);
    assert_eq!(clock.delays, vec![Duration::from_millis(10); 2]);
    assert!(
        result
            .cases
            .iter()
            .all(|case| case.outcome == FuzzCaseOutcome::Timeout)
    );
}

#[test]
fn evidence_truncation_never_turns_a_correlated_response_into_timeout() {
    let mut authorizer = RecordingAuthorizer::default();
    let mut executor = RecordingExecutor {
        response: Some(vec![0xaa, 0xbb]),
        ..RecordingExecutor::default()
    };
    let mut clock = RecordingClock::default();
    let result = fuzz_live(
        &FuzzRequest {
            cases: 1,
            strategies: vec![FuzzStrategy::BitFlip],
            targets: vec!["2.bytes".parse().unwrap()],
            limits: FuzzLimits {
                max_evidence_bytes: 1,
                ..FuzzLimits::default()
            },
            ..FuzzRequest::default()
        },
        FuzzLiveOptions::default(),
        udp_fuzz_packet(),
        fuzz_protocol_registry(),
        &mut authorizer,
        &mut executor,
        &mut clock,
    )
    .unwrap();
    assert_eq!(result.cases[0].outcome, FuzzCaseOutcome::Response);
    assert!(result.cases[0].responses.is_empty());
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "fuzz.evidence_limit")
    );
}

#[test]
fn preparation_and_live_evidence_share_the_aggregate_byte_budget() {
    let base_request = FuzzRequest {
        cases: 1,
        strategies: vec![FuzzStrategy::BitFlip],
        targets: vec!["2.bytes".parse().unwrap()],
        ..FuzzRequest::default()
    };
    let prepared = super::mutation::prepare(
        &base_request,
        udp_fuzz_packet(),
        fuzz_protocol_registry(),
        &mut Deadline::new(base_request.limits.max_duration),
    )
    .unwrap();
    let max_total_bytes = usize::try_from(prepared.retained_byte_count).unwrap() + 1;
    let mut request = base_request;
    request.limits.max_packet_bytes = max_total_bytes;
    request.limits.max_total_bytes = max_total_bytes;
    request.limits.max_evidence_bytes = max_total_bytes;
    request.build.max_packet_size = max_total_bytes;
    let mut executor = RecordingExecutor {
        response: Some(vec![0xaa, 0xbb]),
        ..RecordingExecutor::default()
    };

    let result = fuzz_live(
        &request,
        FuzzLiveOptions::default(),
        udp_fuzz_packet(),
        fuzz_protocol_registry(),
        &mut RecordingAuthorizer::default(),
        &mut executor,
        &mut RecordingClock::default(),
    )
    .unwrap();

    assert_eq!(result.cases[0].outcome, FuzzCaseOutcome::Response);
    assert!(result.cases[0].responses.is_empty());
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "fuzz.evidence_limit")
    );
}

#[test]
fn inconsistent_executor_statistics_fail_closed() {
    let mut authorizer = RecordingAuthorizer::default();
    let mut executor = RecordingExecutor {
        invalid_statistics: true,
        ..RecordingExecutor::default()
    };
    let mut clock = RecordingClock::default();
    let result = fuzz_live(
        &FuzzRequest {
            cases: 1,
            strategies: vec![FuzzStrategy::BitFlip],
            targets: vec!["2.bytes".parse().unwrap()],
            ..FuzzRequest::default()
        },
        FuzzLiveOptions::default(),
        udp_fuzz_packet(),
        fuzz_protocol_registry(),
        &mut authorizer,
        &mut executor,
        &mut clock,
    );
    assert!(matches!(result, Err(FuzzError::InvalidEvidence { .. })));
}

#[test]
fn executor_cannot_turn_a_response_after_the_case_deadline_into_success() {
    let mut authorizer = RecordingAuthorizer::default();
    let mut executor = RecordingExecutor {
        response: Some(vec![0xaa]),
        response_delay: Duration::from_millis(2),
        ..RecordingExecutor::default()
    };
    let result = fuzz_live(
        &FuzzRequest {
            cases: 1,
            strategies: vec![FuzzStrategy::BitFlip],
            targets: vec!["2.bytes".parse().unwrap()],
            ..FuzzRequest::default()
        },
        FuzzLiveOptions {
            timeout: Duration::from_millis(1),
            ..FuzzLiveOptions::default()
        },
        udp_fuzz_packet(),
        fuzz_protocol_registry(),
        &mut authorizer,
        &mut executor,
        &mut RecordingClock::default(),
    );

    assert!(matches!(result, Err(FuzzError::InvalidEvidence { .. })));
}

#[test]
fn malformed_raw_wire_values_remain_explicit_in_reproduction_recipe() {
    let result = fuzz(
        &FuzzRequest {
            first_case: 1,
            cases: 1,
            strategies: vec![FuzzStrategy::Malformed],
            targets: vec!["1.checksum".parse().unwrap()],
            build: BuildOptions {
                mode: BuildMode::Permissive,
                ..BuildOptions::default()
            },
            ..FuzzRequest::default()
        },
        udp_fuzz_packet(),
        fuzz_protocol_registry(),
    )
    .unwrap();
    let recipe = PacketDocument::from_packet(&result.cases[0].recipe);
    assert!(matches!(
        recipe.layers[1].fields["checksum"],
        FieldValue::Bytes(_) | FieldValue::Unsigned(_)
    ));
    let udp = result.cases[0]
        .recipe
        .get::<Udp>()
        .expect("UDP remains present");
    assert!(!matches!(udp.checksum, WireValue::Auto));
}
