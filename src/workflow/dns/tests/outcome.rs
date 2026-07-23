// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

struct LocalAuthorizer;

impl Authorizer for LocalAuthorizer {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        assert_eq!(
            target,
            &Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53)))
        );
        Ok(Authorized {
            declared: target.to_string(),
            addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))],
        })
    }

    fn authorize_operation(
        &mut self,
        packets: u64,
        _maximum_wire_bytes: u64,
    ) -> Result<(), BoundaryError> {
        assert_eq!(packets, 1);
        Ok(())
    }
}

pub(super) struct PayloadExecutor {
    pub(super) payload: Bytes,
}

fn decoded_dns_payload(
    exchange: &DnsExchange,
    payload: Bytes,
    timestamp: SystemTime,
) -> DecodedPacket {
    let mut response_packet = Packet::new();
    response_packet
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 53),
            destination: Ipv4Addr::UNSPECIFIED,
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: exchange.probe.server_port,
            destination_port: exchange.probe.source_port,
            ..Udp::default()
        })
        .push(Raw::new(payload.clone()));
    DecodedPacket {
        packet: response_packet,
        original: payload.clone(),
        frame: Frame::new(timestamp, LinkType::RAW, payload).unwrap(),
        layout: crate::packet::layout::PacketLayout::default(),
        diagnostics: Vec::new(),
    }
}

impl DnsExecutor for PayloadExecutor {
    fn execute(&mut self, exchange: &DnsExchange) -> Result<DnsExchangeExecution, BoundaryError> {
        let sent_at = UNIX_EPOCH + Duration::from_secs(10);
        Ok(DnsExchangeExecution {
            sent: exchange.probe.packet(),
            sent_evidence: Frame::new(sent_at, LinkType::RAW, exchange.probe.query.clone())
                .unwrap(),
            responses: vec![DnsMatchedResponse {
                response: decoded_dns_payload(
                    exchange,
                    self.payload.clone(),
                    sent_at + Duration::from_millis(2),
                ),
                latency: Duration::from_millis(2),
            }],
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: exchange.probe.query.len() as u64,
                elapsed: Duration::from_millis(2),
                ..Stats::default()
            },
        })
    }
}

pub(super) fn single_attempt_request() -> DnsRequest {
    DnsRequest {
        server: Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))),
        address_family: AddressFamily::Ipv4,
        server_port: 53,
        source_port: 50_000,
        query_name: "www.example.test".to_owned(),
        query_type: DnsQueryType::A,
        transaction_id: 77,
        recursion_desired: true,
        attempts: 1,
        timeout: Duration::from_millis(10),
        queries_per_second: None,
        limits: DnsLimits::default(),
    }
}

#[test]
fn workflow_outcomes_distinguish_valid_truncated_unrelated_and_decode_failure() {
    let valid = fixture_response(
        77,
        0,
        "www.example.test",
        DnsQueryType::A,
        &[FixtureRecord::in_class(
            "www.example.test",
            1,
            vec![192, 0, 2, 10],
        )],
        &[],
        &[],
    );
    let truncated = fixture_response(
        77,
        DNS_FLAG_TRUNCATED,
        "www.example.test",
        DnsQueryType::A,
        &[],
        &[],
        &[],
    );
    let unrelated = fixture_response(78, 0, "www.example.test", DnsQueryType::A, &[], &[], &[]);
    for (payload, outcome, status) in [
        (
            Bytes::from(valid),
            DnsOutcome::Response,
            DnsAttemptStatus::Response,
        ),
        (
            Bytes::from(truncated),
            DnsOutcome::Truncated,
            DnsAttemptStatus::Truncated,
        ),
        (
            Bytes::from(unrelated),
            DnsOutcome::Unrelated,
            DnsAttemptStatus::Unrelated,
        ),
        (
            Bytes::from_static(b"malformed"),
            DnsOutcome::DecodeFailure,
            DnsAttemptStatus::DecodeFailure,
        ),
    ] {
        let result = dns(
            &single_attempt_request(),
            &mut LocalAuthorizer,
            &default_registry().unwrap(),
            &mut PayloadExecutor { payload },
            &mut NoopClock,
        )
        .unwrap();
        assert_eq!(result.outcome, outcome);
        assert_eq!(result.attempts[0].status, status);
        assert!(result.attempts[0].response.is_some());
    }
}

#[test]
fn unsolicited_dns_response_after_the_deadline_remains_a_timeout() {
    struct LateUnsolicitedExecutor {
        payload: Bytes,
    }

    impl DnsExecutor for LateUnsolicitedExecutor {
        fn execute(
            &mut self,
            exchange: &DnsExchange,
        ) -> Result<DnsExchangeExecution, BoundaryError> {
            let mut execution = PayloadExecutor {
                payload: self.payload.clone(),
            }
            .execute(exchange)?;
            let mut response = execution.responses.remove(0).response;
            response.frame.timestamp =
                execution.sent_evidence.timestamp + exchange.timeout + Duration::from_millis(1);
            execution.unsolicited.push(response);
            Ok(execution)
        }
    }

    let payload = fixture_response(
        77,
        0,
        "www.example.test",
        DnsQueryType::A,
        &[FixtureRecord::in_class(
            "www.example.test",
            1,
            vec![192, 0, 2, 10],
        )],
        &[],
        &[],
    );
    let result = dns(
        &single_attempt_request(),
        &mut LocalAuthorizer,
        &default_registry().unwrap(),
        &mut LateUnsolicitedExecutor {
            payload: Bytes::from(payload),
        },
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(result.outcome, DnsOutcome::Timeout);
    assert_eq!(result.attempts[0].status, DnsAttemptStatus::Timeout);
}

#[test]
fn matched_response_deadline_uses_monotonic_latency_despite_wall_clock_skew() {
    struct PreSendMatchedExecutor {
        payload: Bytes,
    }

    impl DnsExecutor for PreSendMatchedExecutor {
        fn execute(
            &mut self,
            exchange: &DnsExchange,
        ) -> Result<DnsExchangeExecution, BoundaryError> {
            let mut execution = PayloadExecutor {
                payload: self.payload.clone(),
            }
            .execute(exchange)?;
            execution.responses[0].response.frame.timestamp = execution
                .sent_evidence
                .timestamp
                .checked_sub(Duration::from_millis(1))
                .unwrap();
            Ok(execution)
        }
    }

    let payload = fixture_response(
        77,
        0,
        "www.example.test",
        DnsQueryType::A,
        &[FixtureRecord::in_class(
            "www.example.test",
            1,
            vec![192, 0, 2, 10],
        )],
        &[],
        &[],
    );
    let result = dns(
        &single_attempt_request(),
        &mut LocalAuthorizer,
        &default_registry().unwrap(),
        &mut PreSendMatchedExecutor {
            payload: Bytes::from(payload),
        },
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(result.outcome, DnsOutcome::Response);
    assert!(result.attempts[0].received_at.unwrap() < result.attempts[0].sent_at);
}

#[test]
fn canonical_dns_selection_is_independent_of_matched_and_unsolicited_source_order() {
    struct CompetingExecutor {
        preferred_is_matched: bool,
        preferred: Bytes,
        other: Bytes,
    }

    impl DnsExecutor for CompetingExecutor {
        fn execute(
            &mut self,
            exchange: &DnsExchange,
        ) -> Result<DnsExchangeExecution, BoundaryError> {
            let sent_at = UNIX_EPOCH + Duration::from_secs(10);
            let preferred = decoded_dns_payload(
                exchange,
                self.preferred.clone(),
                sent_at + Duration::from_millis(2),
            );
            let other = decoded_dns_payload(
                exchange,
                self.other.clone(),
                sent_at + Duration::from_millis(3),
            );
            let (responses, unsolicited) = if self.preferred_is_matched {
                (
                    vec![DnsMatchedResponse {
                        response: preferred,
                        latency: Duration::from_millis(2),
                    }],
                    vec![other],
                )
            } else {
                (
                    vec![DnsMatchedResponse {
                        response: other,
                        latency: Duration::from_millis(3),
                    }],
                    vec![preferred],
                )
            };
            Ok(DnsExchangeExecution {
                sent: exchange.probe.packet(),
                sent_evidence: Frame::new(sent_at, LinkType::RAW, exchange.probe.query.clone())
                    .unwrap(),
                responses,
                unsolicited,
                undecoded: Vec::new(),
                diagnostics: Vec::new(),
                stats: Stats {
                    packets_attempted: 1,
                    packets_completed: 1,
                    bytes: exchange.probe.query.len() as u64,
                    ..Stats::default()
                },
            })
        }
    }

    let preferred = Bytes::from(fixture_response(
        77,
        0,
        "www.example.test",
        DnsQueryType::A,
        &[],
        &[],
        &[],
    ));
    let other = Bytes::from(fixture_response(
        77,
        3,
        "www.example.test",
        DnsQueryType::A,
        &[],
        &[],
        &[],
    ));
    for preferred_is_matched in [true, false] {
        let result = dns(
            &single_attempt_request(),
            &mut LocalAuthorizer,
            &default_registry().unwrap(),
            &mut CompetingExecutor {
                preferred_is_matched,
                preferred: preferred.clone(),
                other: other.clone(),
            },
            &mut NoopClock,
        )
        .unwrap();

        assert_eq!(result.attempts[0].response_code, Some(0));
        assert_eq!(
            result.attempts[0].received_at,
            Some(UNIX_EPOCH + Duration::from_secs(10) + Duration::from_millis(2))
        );
    }
}
