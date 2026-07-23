// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

pub(super) struct NoopClock;

impl Clock for NoopClock {
    type Error = Infallible;

    fn sleep(&mut self, _delay: Duration) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct ScriptedResolver {
    pub(super) calls: Arc<AtomicUsize>,
    answers: Arc<Mutex<VecDeque<Vec<IpAddr>>>>,
}

impl ScriptedResolver {
    pub(super) fn new(answers: impl IntoIterator<Item = Vec<IpAddr>>) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            answers: Arc::new(Mutex::new(answers.into_iter().collect())),
        }
    }
}

impl HostnameResolver for ScriptedResolver {
    fn resolve(
        &self,
        hostname: &Hostname,
        _limit: usize,
    ) -> Result<Vec<IpAddr>, TargetResolutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.answers
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| TargetResolutionError::NoAddresses {
                hostname: hostname.to_string(),
            })
    }
}

#[derive(Default)]
pub(super) struct TimeoutExecutor {
    pub(super) calls: usize,
    pub(super) addresses: Vec<IpAddr>,
}

impl DnsExecutor for TimeoutExecutor {
    fn execute(&mut self, exchange: &DnsExchange) -> Result<DnsExchangeExecution, BoundaryError> {
        self.calls += 1;
        self.addresses.push(exchange.probe.server_address);
        Ok(DnsExchangeExecution {
            sent: exchange.probe.packet(),
            sent_evidence: Frame::new(
                UNIX_EPOCH + Duration::from_secs(u64::from(exchange.probe.attempt)),
                LinkType::RAW,
                exchange.probe.query.clone(),
            )
            .unwrap(),
            responses: Vec::new(),
            unsolicited: Vec::new(),
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

fn dns_validation_fixture() -> (DnsProbe, DnsExchangeExecution) {
    let query = encode_dns_query("www.example.test", DnsQueryType::A, 77, true).unwrap();
    let probe = DnsProbe {
        attempt: 1,
        server_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53)),
        server_port: 53,
        source_port: 50_000,
        transaction_id: 77,
        query_name: "www.example.test.".to_owned(),
        query_type: DnsQueryType::A,
        query,
    };
    let execution = TimeoutExecutor::default()
        .execute(&DnsExchange {
            probe: probe.clone(),
            timeout: Duration::from_millis(10),
            max_responses: 1,
        })
        .unwrap();
    (probe, execution)
}

fn invalid_dns_evidence_message(
    result: Result<(), DnsError>,
    expected_sequence: Option<u64>,
) -> String {
    let error = result.unwrap_err();
    assert_eq!(error.sequence(), expected_sequence);
    assert_eq!(error.classification().code, "internal.dns_evidence");
    match error {
        DnsError::InvalidEvidence {
            attempt: 1,
            message,
        } => message,
        other => panic!("expected invalid DNS evidence, received {other:?}"),
    }
}

#[test]
fn executor_cannot_underreport_exact_dns_wire_bytes() {
    let (probe, mut execution) = dns_validation_fixture();
    execution.stats.bytes = 0;

    assert_eq!(
        invalid_dns_evidence_message(
            validate_dns_execution(
                &probe,
                &execution,
                DnsLimits::default(),
                Duration::from_millis(10),
            ),
            Some(0),
        ),
        format!(
            "successful exchange reported 0 sent bytes for {} exact frame bytes",
            probe.query.len()
        )
    );
}

#[test]
fn dns_executor_response_frames_and_deadlines_preserve_exact_errors() {
    let (probe, mut malformed) = dns_validation_fixture();
    malformed.responses.push(DnsMatchedResponse {
        response: DecodedPacket {
            packet: Packet::new(),
            original: Bytes::from_static(&[2]),
            frame: Frame::new(UNIX_EPOCH, LinkType::RAW, vec![1]).unwrap(),
            layout: crate::packet::layout::PacketLayout::default(),
            diagnostics: Vec::new(),
        },
        latency: Duration::from_millis(1),
    });
    assert_eq!(
        invalid_dns_evidence_message(
            validate_dns_execution(
                &probe,
                &malformed,
                DnsLimits::default(),
                Duration::from_millis(10),
            ),
            Some(0),
        ),
        "matched response original bytes differ from its exact frame"
    );

    let mut late = malformed;
    late.responses[0].response.original = Bytes::from_static(&[1]);
    late.responses[0].latency = Duration::from_millis(11);
    assert_eq!(
        invalid_dns_evidence_message(
            validate_dns_execution(
                &probe,
                &late,
                DnsLimits::default(),
                Duration::from_millis(10),
            ),
            Some(0),
        ),
        "matched response latency 11ms exceeds timeout 10ms"
    );
}

#[test]
fn dns_executor_statistics_and_aggregate_limits_preserve_exact_errors() {
    let (probe, execution) = dns_validation_fixture();

    let mut packet_statistics = execution.clone();
    packet_statistics.stats.packets_completed = 0;
    assert_eq!(
        invalid_dns_evidence_message(
            validate_dns_execution(
                &probe,
                &packet_statistics,
                DnsLimits::default(),
                Duration::from_millis(10),
            ),
            Some(0),
        ),
        "successful exchange statistics must account for exactly one DNS query"
    );

    let mut capture_statistics = execution.clone();
    capture_statistics.stats.capture.dropped_bytes = 1;
    assert_eq!(
        invalid_dns_evidence_message(
            validate_dns_execution(
                &probe,
                &capture_statistics,
                DnsLimits::default(),
                Duration::from_millis(10),
            ),
            Some(0),
        ),
        "capture statistics are invalid: capture backend returned invalid statistics: dropped bytes were reported without a dropped frame"
    );

    let mut captured = execution;
    captured
        .undecoded
        .push(Frame::new(UNIX_EPOCH, LinkType::RAW, Bytes::from_static(&[1, 2])).unwrap());
    assert_eq!(
        invalid_dns_evidence_message(
            validate_dns_execution(
                &probe,
                &captured,
                DnsLimits {
                    max_evidence_frames: 0,
                    ..DnsLimits::default()
                },
                Duration::from_millis(10),
            ),
            Some(0),
        ),
        "executor returned 1 frames beyond max_evidence_frames=0"
    );
    assert_eq!(
        invalid_dns_evidence_message(
            validate_dns_execution(
                &probe,
                &captured,
                DnsLimits {
                    max_evidence_bytes: 1,
                    ..DnsLimits::default()
                },
                Duration::from_millis(10),
            ),
            Some(0),
        ),
        "executor returned 2 frame bytes beyond max_evidence_bytes=1"
    );
}

#[test]
fn dns_evidence_validation_keeps_multi_failure_precedence() {
    let (probe, mut execution) = dns_validation_fixture();
    execution.stats.packets_attempted = 0;
    execution.stats.bytes = 0;
    execution.stats.capture.dropped_bytes = 1;
    execution.responses.push(DnsMatchedResponse {
        response: DecodedPacket {
            packet: Packet::new(),
            original: Bytes::from_static(&[2]),
            frame: Frame::new(UNIX_EPOCH, LinkType::RAW, vec![1]).unwrap(),
            layout: crate::packet::layout::PacketLayout::default(),
            diagnostics: Vec::new(),
        },
        latency: Duration::from_millis(11),
    });
    let limits = DnsLimits {
        max_evidence_frames: 0,
        max_evidence_bytes: 0,
        ..DnsLimits::default()
    };

    assert_eq!(
        invalid_dns_evidence_message(
            validate_dns_execution(&probe, &execution, limits, Duration::from_millis(10)),
            Some(0),
        ),
        "successful exchange statistics must account for exactly one DNS query"
    );

    execution.stats.packets_attempted = 1;
    assert_eq!(
        invalid_dns_evidence_message(
            validate_dns_execution(&probe, &execution, limits, Duration::from_millis(10)),
            Some(0),
        ),
        format!(
            "successful exchange reported 0 sent bytes for {} exact frame bytes",
            probe.query.len()
        )
    );

    execution.stats.bytes = probe.query.len() as u64;
    assert_eq!(
        invalid_dns_evidence_message(
            validate_dns_execution(&probe, &execution, limits, Duration::from_millis(10)),
            Some(0),
        ),
        "capture statistics are invalid: capture backend returned invalid statistics: dropped bytes were reported without a dropped frame"
    );

    execution.stats.capture = crate::net::capture::Statistics::default();
    assert_eq!(
        invalid_dns_evidence_message(
            validate_dns_execution(&probe, &execution, limits, Duration::from_millis(10)),
            Some(0),
        ),
        "matched response original bytes differ from its exact frame"
    );
}

#[test]
fn dns_evidence_diagnostics_preserve_casing_deduplication_and_response_priority() {
    struct TwoAttemptAuthorizer;

    impl Authorizer for TwoAttemptAuthorizer {
        fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
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
            assert_eq!(packets, 2);
            Ok(())
        }
    }

    struct ResponseAndUndecodedExecutor;

    impl DnsExecutor for ResponseAndUndecodedExecutor {
        fn execute(
            &mut self,
            exchange: &DnsExchange,
        ) -> Result<DnsExchangeExecution, BoundaryError> {
            let mut execution = PayloadExecutor {
                payload: Bytes::from_static(b"malformed"),
            }
            .execute(exchange)?;
            execution.undecoded.push(
                Frame::new(
                    execution.sent_evidence.timestamp,
                    LinkType::RAW,
                    vec![exchange.probe.attempt as u8],
                )
                .unwrap(),
            );
            Ok(execution)
        }
    }

    let mut request = single_attempt_request();
    request.attempts = 2;
    request.limits.max_evidence_frames = 3;
    request.limits.max_evidence_bytes = 1_024;
    request.limits.max_undecoded = 3;
    let result = dns(
        &request,
        &mut TwoAttemptAuthorizer,
        &default_registry().unwrap(),
        &mut ResponseAndUndecodedExecutor,
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(result.attempts.len(), 2);
    assert!(
        result
            .attempts
            .iter()
            .all(|attempt| attempt.response.is_some())
    );
    assert_eq!(result.undecoded.len(), 1);
    let diagnostics = result
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == "dns.evidence_limit")
        .collect::<Vec<_>>();
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].message,
        "DNS evidence exceeded 3 frame(s) or 1024 byte(s); later exact frames were omitted"
    );
}
