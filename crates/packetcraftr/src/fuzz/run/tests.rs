// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::Ipv4Addr;
use std::time::{Instant, UNIX_EPOCH};

use packetcraftr_core::protocol::{network::Ipv4, transport::Udp};

use super::*;
use crate::test_fixtures::NoopClock;

#[derive(Default)]
struct ExecutorFixture {
    timeouts: Vec<Duration>,
    response_latency: Option<Duration>,
}

impl Executor<ExecutionCase> for ExecutorFixture {
    fn execute(&mut self, request: &ExecutionCase) -> Result<Execution, crate::BoundaryError> {
        self.timeouts.push(request.timeout);
        let sent = crate::evidence::test_sent_packet(request.packet.clone());
        let responses = self
            .response_latency
            .filter(|_| self.timeouts.len() == 2)
            .map(|latency| crate::exchange::Response {
                request_index: 0,
                response: crate::probe::test_fixtures::decoded_packet(
                    request.packet.clone(),
                    UNIX_EPOCH,
                    sent.wire_bytes(),
                    Vec::new(),
                ),
                latency,
            })
            .into_iter()
            .collect();
        Ok(Execution {
            permit: request.permit,
            stats: crate::Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: u64::try_from(sent.bytes_sent()).unwrap(),
                elapsed: if self.timeouts.len() == 1 {
                    Duration::from_millis(400)
                } else {
                    request.timeout
                },
                ..crate::Stats::default()
            },
            sent,
            responses,
            unmatched: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
        })
    }
}

fn request() -> packet_fuzz::Request {
    packet_fuzz::Request {
        cases: 2,
        strategies: vec![packet_fuzz::Strategy::BitFlip],
        targets: vec!["2.bytes".parse().unwrap()],
        limits: packet_fuzz::Limits {
            max_duration: Duration::from_secs(5),
            ..packet_fuzz::Limits::default()
        },
        ..packet_fuzz::Request::default()
    }
}

fn phase(request: &packet_fuzz::Request, spent: Duration) -> ExecutionPhase<'_> {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let live = LiveOptions {
        timeout: Duration::from_millis(800),
        cases_per_second: Some(5),
        ..LiveOptions::default()
    };
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 1),
            ..Ipv4::default()
        })
        .push(Udp {
            destination_port: 9,
            ..Udp::default()
        })
        .push(packetcraftr_core::layer::Raw::new(
            bytes::Bytes::from_static(b"case"),
        ));
    let prepared = prepare_campaign(
        request,
        live,
        packet,
        &registry,
        &mut Deadline::new(request.limits.max_duration),
    )
    .expect("bounded prepared campaign");
    let now = Instant::now();
    let mut deadline = Deadline::with_time_source(request.limits.max_duration, move || now);
    let _ = deadline.account(spent);
    ExecutionPhase {
        request,
        live,
        live_dissector: Dissector::new(Arc::clone(&registry)),
        registry,
        deadline,
        cases: prepared.cases,
        stats: Stats::default(),
        evidence: Budget::default(),
        diagnostics: DiagnosticLog::default(),
        scheduled_delay: Duration::ZERO,
    }
}

#[test]
fn live_cases_share_the_remaining_budget_after_execution_and_pacing() {
    let request = request();
    let mut executor = ExecutorFixture {
        response_latency: Some(Duration::from_millis(200)),
        ..ExecutorFixture::default()
    };
    let mut cases = Vec::new();
    let summary = phase(&request, Duration::from_millis(4200))
        .execute(&mut executor, &mut NoopClock, &mut |case, _| {
            cases.push(case);
            Ok(())
        })
        .expect("response at the clipped boundary remains valid");
    assert_eq!(
        executor.timeouts,
        [Duration::from_millis(800), Duration::from_millis(200)]
    );
    assert_eq!(summary.stats.elapsed, Duration::from_millis(800));
    assert_eq!(cases[0].outcome, CaseOutcome::Timeout);
    assert_eq!(cases[1].outcome, CaseOutcome::Response);
    assert_eq!(cases[1].responses.len(), 1);
}

#[test]
fn live_case_evidence_beyond_the_clipped_timeout_is_rejected_before_publication() {
    let request = request();
    let mut executor = ExecutorFixture {
        response_latency: Some(Duration::from_millis(250)),
        ..ExecutorFixture::default()
    };
    let mut published = 0;
    let error = phase(&request, Duration::from_millis(4200))
        .execute(&mut executor, &mut NoopClock, &mut |_, _| {
            published += 1;
            Ok(())
        })
        .expect_err("250 ms latency exceeds the clipped 200 ms timeout");
    assert!(matches!(
        error,
        Error::InvalidEvidence { case_index: 1, .. }
    ));
    assert_eq!(published, 1);
}

#[test]
fn zero_and_exhausted_live_budgets_never_execute_or_publish() {
    let request = request();
    for spent in [Duration::from_secs(5), Duration::from_millis(5001)] {
        let mut executor = ExecutorFixture::default();
        let error = phase(&request, spent)
            .execute(&mut executor, &mut NoopClock, &mut |_, _| {
                panic!("an unexecuted case must not be published")
            })
            .expect_err("no remaining execution budget");
        assert!(matches!(error, Error::DurationLimit { .. }));
        assert!(executor.timeouts.is_empty());
    }
}
