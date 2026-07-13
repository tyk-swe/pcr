#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;
    use crate::packet::internal::{BuildMode, PacketDocument, Raw, WireValue};
    use crate::protocol::internal::{default_registry, Ipv4, Udp};

    fn registry() -> Arc<ProtocolRegistry> {
        Arc::new(default_registry().unwrap())
    }

    fn packet() -> Packet {
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
    fn same_seed_and_configuration_produce_identical_cases_and_bytes() {
        let request = FuzzRequest {
            seed: 0x1234_5678,
            cases: 128,
            ..FuzzRequest::default()
        };
        let first = fuzz(&request, packet(), registry()).unwrap();
        let second = fuzz(&request, packet(), registry()).unwrap();
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
        let campaign = fuzz(&request, packet(), registry()).unwrap();
        let expected = &campaign.cases[19];
        let reproduced = fuzz(
            &FuzzRequest {
                first_case: expected.index,
                cases: 1,
                ..request
            },
            packet(),
            registry(),
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
            packet(),
            registry(),
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
            assert!(bounded_value_size(
                &FieldValue::List(values),
                limits.max_field_bytes,
                limits.max_list_items,
                0,
            )
            .is_some());
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
            packet(),
            registry(),
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
            packet(),
            registry(),
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
        let error = fuzz(&FuzzRequest::default(), oversized, registry()).unwrap_err();
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
        let base = packet();
        let strict = fuzz(
            &FuzzRequest {
                seed: 1,
                cases: 8,
                strategies: vec![FuzzStrategy::Malformed],
                targets: vec!["1.length".parse().unwrap()],
                ..FuzzRequest::default()
            },
            base.clone(),
            registry(),
        )
        .unwrap();
        assert!(strict
            .cases
            .iter()
            .any(|case| case.outcome == FuzzCaseOutcome::Rejected));

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
            registry(),
        )
        .unwrap();
        assert!(permissive.cases.iter().any(|case| case
            .built
            .as_ref()
            .is_some_and(|built| built.requires_live_opt_in)));
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
        ) -> Result<(), FuzzAuthorizationError> {
            self.calls += 1;
            assert!(!packets.is_empty());
            if self.deny {
                return Err(FuzzAuthorizationError::new(
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
        ) -> Result<FuzzCaseExecution, FuzzExecutionError> {
            self.calls += 1;
            if let Some(delay) = self.sleep {
                std::thread::sleep(delay);
            }
            let built = Builder::new(registry())
                .build(
                    case.packet.clone(),
                    BuildContext::default(),
                    BuildOptions {
                        mode: BuildMode::Permissive,
                        ..BuildOptions::default()
                    },
                )
                .map_err(|source| {
                    FuzzExecutionError::new(
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
                    vec![Frame::new(
                        std::time::UNIX_EPOCH + self.response_delay,
                        LinkType::BSD_RAW,
                        bytes.clone(),
                    )
                    .unwrap()]
                })
                .unwrap_or_default();
            Ok(FuzzCaseExecution {
                stats: FuzzExecutionStats {
                    packets_attempted: 1,
                    packets_completed: u64::from(!self.invalid_statistics),
                    bytes: built.bytes.len() as u64,
                    ..FuzzExecutionStats::default()
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
            packet(),
            registry(),
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
            packet(),
            registry(),
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
            packet(),
            registry(),
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
            packet(),
            registry(),
            &mut authorizer,
            &mut executor,
            &mut clock,
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
            packet(),
            registry(),
            &mut authorizer,
            &mut executor,
            &mut clock,
        )
        .unwrap();
        assert_eq!(result.mode, FuzzMode::Live);
        assert_eq!(executor.calls, 3);
        assert_eq!(clock.delays, vec![Duration::from_millis(10); 2]);
        assert!(result
            .cases
            .iter()
            .all(|case| case.outcome == FuzzCaseOutcome::Timeout));
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
            packet(),
            registry(),
            &mut authorizer,
            &mut executor,
            &mut clock,
        )
        .unwrap();
        assert_eq!(result.cases[0].outcome, FuzzCaseOutcome::Response);
        assert!(result.cases[0].responses.is_empty());
        assert!(result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "fuzz.evidence_limit"));
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
            packet(),
            registry(),
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
            packet(),
            registry(),
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
            packet(),
            registry(),
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
}
