// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::net::IpAddr;
use std::result::Result;
use std::time::Duration;

use super::super::engine::{fuzz, fuzz_live};
use super::super::error::FuzzError;
use super::super::model::{
    FuzzAuthorizer, FuzzCaseExecution, FuzzCaseOutcome, FuzzExecutionCase, FuzzExecutor,
    FuzzLimits, FuzzLiveOptions, FuzzMode, FuzzRequest, FuzzStrategy,
};
use super::super::mutation::prepare;
use super::{fuzz_protocol_registry, udp_fuzz_packet};
use crate::clock::Clock;
use crate::{BoundaryError, Stats};
use packetcraftr_capture::{Frame, LinkType};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::{Classification, Kind};
use packetcraftr_packet::{
    Packet,
    build::{BuildContext, BuildMode, BuildOptions, Builder},
    document::PacketDocument,
    field::{FieldValue, WireValue},
};
use packetcraftr_protocol::transport::Udp;

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
    let prepared = prepare(
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
