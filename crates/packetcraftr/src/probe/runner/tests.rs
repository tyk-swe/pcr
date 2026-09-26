// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Instant, UNIX_EPOCH};

use bytes::Bytes;
use packetcraftr_core::{layer::Raw, packet::Packet};

use super::*;
use crate::BoundaryError;
use crate::evidence::ExecutionPermit;
use crate::execution::evidence::EvidenceLimits;
use crate::probe::{ErrorKind, Workflow};
use crate::test_support::RecordingClock;
use crate::test_support::{decoded_packet, evidence_frame};

#[derive(Clone, Debug, PartialEq, Eq)]
struct TestProbe(u64);

impl Sequenced for TestProbe {
    fn sequence(&self) -> u64 {
        self.0
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Answer {
    responder: IpAddr,
    latency: Duration,
    frame: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Probe {
        sequence: u64,
        reply: Option<Answer>,
    },
    Undecoded(Vec<u8>),
    Diagnostic(String),
}

fn probe(sequence: u64) -> Event {
    Event::Probe {
        sequence,
        reply: None,
    }
}

fn diagnostic(code: &str) -> Event {
    Event::Diagnostic(code.to_owned())
}

/// Reads a response's first byte as its rank and its second as the
/// responder's last documentation-address octet; a zero rank is uncorrelated.
#[derive(Default)]
struct TestClassifier {
    terminal: Option<u64>,
}

fn responder(octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, octet))
}

impl Classifier for TestClassifier {
    type Probe = TestProbe;
    type Observation = (u8, IpAddr);
    type Event = Event;

    fn sent_matches(&self, _probe: &TestProbe, _sent: &Packet) -> bool {
        true
    }

    fn classify(
        &self,
        _probe: &TestProbe,
        _sent: &SentPacket,
        response: &DecodedPacket,
    ) -> Option<(u8, IpAddr)> {
        let bytes = response.frame.bytes();
        (bytes[0] > 0).then(|| (bytes[0], responder(bytes[1])))
    }

    fn rank(&self, observation: &(u8, IpAddr)) -> u8 {
        observation.0
    }

    fn responder(&self, observation: &(u8, IpAddr)) -> IpAddr {
        observation.1
    }

    fn evidence(
        &mut self,
        probe: &TestProbe,
        _sent: &SentPacket,
        outcome: Outcome<(u8, IpAddr)>,
    ) -> Event {
        Event::Probe {
            sequence: probe.0,
            reply: match outcome {
                Outcome::Timeout => None,
                Outcome::Reply(reply) => Some(Answer {
                    responder: reply.observation.1,
                    latency: reply.latency,
                    frame: reply.frame.map(|frame| frame.bytes().to_vec()),
                }),
            },
        }
    }

    fn undecoded(&self, _probes: &[TestProbe], frame: Frame) -> Event {
        Event::Undecoded(frame.bytes().to_vec())
    }

    fn diagnostic(&self, diagnostic: Diagnostic) -> Event {
        Event::Diagnostic(diagnostic.code.to_string())
    }

    fn ends_operation(&self, event: &Event) -> bool {
        matches!(event, Event::Probe { sequence, .. } if Some(*sequence) == self.terminal)
    }
}

/// What the fake executor returns for one batch, beyond one exact send
/// receipt per probe.
#[derive(Default)]
struct Script {
    /// `(request index, frame bytes, latency in milliseconds)` in arrival order.
    responses: Vec<(usize, &'static [u8], u64)>,
    undecoded: Vec<&'static [u8]>,
    diagnostics: Vec<Diagnostic>,
    foreign_permit: bool,
}

/// Returns scripted executions in order (no responses once the script runs
/// out) and records every batch it was handed.
#[derive(Default)]
struct ScriptedExecutor {
    scripts: VecDeque<Script>,
    executed: Vec<Batch<TestProbe>>,
}

impl ScriptedExecutor {
    fn new(scripts: impl IntoIterator<Item = Script>) -> Self {
        Self {
            scripts: scripts.into_iter().collect(),
            executed: Vec::new(),
        }
    }
}

impl Executor<Batch<TestProbe>> for ScriptedExecutor {
    fn execute(&mut self, batch: &Batch<TestProbe>) -> Result<Execution, BoundaryError> {
        self.executed.push(batch.clone());
        let script = self.scripts.pop_front().unwrap_or_default();
        let sent: Vec<_> = batch
            .probes
            .iter()
            .map(|probe| {
                let mut packet = Packet::new();
                packet.push(Raw::new(Bytes::from(vec![probe.0 as u8])));
                crate::test_support::sent_packet(packet)
            })
            .collect();
        let responses = script
            .responses
            .into_iter()
            .map(
                |(request_index, bytes, latency)| crate::exchange::Response {
                    request_index,
                    response: decoded_packet(Packet::new(), UNIX_EPOCH, bytes, Vec::new()),
                    latency: Duration::from_millis(latency),
                },
            )
            .collect();
        let probes = batch.probes.len() as u64;
        Ok(Execution {
            permit: if script.foreign_permit {
                ExecutionPermit::new()
            } else {
                batch.permit
            },
            stats: Stats {
                packets_attempted: probes,
                packets_completed: probes,
                bytes: probes,
                elapsed: Duration::from_millis(100),
                ..Stats::default()
            },
            sent,
            responses,
            unsolicited: Vec::new(),
            undecoded: script
                .undecoded
                .into_iter()
                .map(|bytes| evidence_frame(UNIX_EPOCH, bytes))
                .collect(),
            diagnostics: script.diagnostics,
        })
    }
}

/// Plans `sizes.len()` consecutive batches with consecutive probe sequences.
fn batches(sizes: &[u64]) -> Vec<Batch<TestProbe>> {
    let mut sequence = 0;
    sizes
        .iter()
        .map(|size| {
            let batch = Batch {
                probes: (sequence..sequence + size).map(TestProbe).collect(),
                timeout: Duration::from_millis(800),
                permit: ExecutionPermit::new(),
                sequence,
            };
            sequence += size;
            batch
        })
        .collect()
}

const LIMITS: EvidenceLimits = EvidenceLimits {
    max_frames: 16,
    max_bytes: 256,
    max_undecoded: 16,
};

struct Run {
    result: Result<Stats, Error>,
    events: Vec<Event>,
    delays: Vec<Duration>,
}

fn run(
    workflow: Workflow,
    limits: EvidenceLimits,
    budget: Duration,
    planned: Vec<Batch<TestProbe>>,
    executor: &mut ScriptedExecutor,
    classifier: TestClassifier,
) -> Run {
    let now = Instant::now();
    let mut deadline = Deadline::with_time_source(budget, move || now);
    let mut clock = RecordingClock::default();
    let mut events = Vec::new();
    let mut evidence = BatchEvidence::new(workflow, limits, classifier, |event, _: &Deadline| {
        events.push(event);
        Ok(())
    });
    let result = run_batches(
        planned,
        Some(5),
        &mut deadline,
        &mut clock,
        executor,
        &mut evidence,
    );
    drop(evidence);
    Run {
        result,
        events,
        delays: clock.delays,
    }
}

#[test]
fn batches_are_paced_by_the_previous_batch_size_and_run_under_their_grant() {
    let planned = batches(&[2, 1, 1]);
    let planned_permits: Vec<_> = planned.iter().map(|batch| batch.permit).collect();
    let mut executor = ScriptedExecutor::default();

    let run = run(
        Workflow::Traceroute,
        LIMITS,
        Duration::from_secs(1),
        planned,
        &mut executor,
        TestClassifier::default(),
    );

    let stats = run.result.expect("three bounded batches");
    assert_eq!(
        run.delays,
        [Duration::from_millis(400), Duration::from_millis(200)]
    );
    assert_eq!(
        executor
            .executed
            .iter()
            .map(|batch| batch.timeout)
            .collect::<Vec<_>>(),
        [800, 500, 200].map(Duration::from_millis)
    );
    let permits: Vec<_> = executor.executed.iter().map(|batch| batch.permit).collect();
    assert!(
        permits
            .iter()
            .all(|permit| !planned_permits.contains(permit))
    );
    assert!(permits[0] != permits[1] && permits[1] != permits[2]);
    assert_eq!(run.events, [probe(0), probe(1), probe(2), probe(3)]);
    assert_eq!(stats.elapsed, Duration::from_millis(900));
    assert_eq!(stats.packets_completed, 4);
}

#[test]
fn evidence_is_judged_against_the_clipped_timeout() {
    // The second batch is clipped from 800 ms to the 300 ms the operation has
    // left, so a 500 ms reply that the plan would have allowed is invalid.
    let mut executor = ScriptedExecutor::new([
        Script::default(),
        Script {
            responses: vec![(0, &[1, 1], 500)],
            ..Script::default()
        },
    ]);

    let run = run(
        Workflow::Scan,
        LIMITS,
        Duration::from_millis(600),
        batches(&[1, 1]),
        &mut executor,
        TestClassifier::default(),
    );

    let error = run.result.expect_err("a reply after the clipped timeout");
    assert!(matches!(
        &error.kind,
        ErrorKind::InvalidEvidence { sequence: 1, message } if message.contains("exceeds timeout 300ms")
    ));
    assert_eq!(run.events, [probe(0)]);
}

#[test]
fn evidence_for_another_permit_is_rejected_before_anything_is_published() {
    let foreign = || Script {
        responses: vec![(0, &[1, 1], 1)],
        diagnostics: vec![Diagnostic::info("fixture.executor", "fixture")],
        foreign_permit: true,
        ..Script::default()
    };
    let mut executor = ScriptedExecutor::new([Script::default(), foreign()]);

    let run = run(
        Workflow::Traceroute,
        LIMITS,
        Duration::from_secs(10),
        batches(&[1, 2]),
        &mut executor,
        TestClassifier::default(),
    );

    let error = run.result.expect_err("foreign evidence is rejected");
    assert!(matches!(
        &error.kind,
        ErrorKind::InvalidEvidence { sequence: 1, message } if message.contains("different execution permit")
    ));
    assert_eq!(run.events, [probe(0)]);

    // A pipelined completion reaches processing without the execution
    // context; processing itself still rejects the foreign permit.
    let batch = batches(&[1]).remove(0);
    let execution = ScriptedExecutor::new([foreign()])
        .execute(&batch)
        .expect("scripted execution");
    let mut events = Vec::new();
    let mut evidence = BatchEvidence::new(
        Workflow::Scan,
        LIMITS,
        TestClassifier::default(),
        |event, _: &Deadline| {
            events.push(event);
            Ok(())
        },
    );
    let error = evidence
        .process(&batch, execution, &Deadline::new(Duration::from_secs(10)))
        .expect_err("foreign evidence is rejected");
    drop(evidence);
    assert!(matches!(
        error.kind,
        ErrorKind::InvalidEvidence { sequence: 0, .. }
    ));
    assert!(events.is_empty());
}

#[test]
fn diagnostics_are_published_before_each_probes_event() {
    let mut executor = ScriptedExecutor::new([
        Script {
            responses: vec![(0, &[1, 1], 1)],
            diagnostics: vec![Diagnostic::info("fixture.executor", "fixture")],
            ..Script::default()
        },
        Script {
            responses: vec![(0, &[1, 2], 1)],
            ..Script::default()
        },
    ]);
    // One retained frame: the second probe's reply exceeds the budget.
    let limits = EvidenceLimits {
        max_frames: 1,
        ..LIMITS
    };

    let run = run(
        Workflow::Traceroute,
        limits,
        Duration::from_secs(10),
        batches(&[1, 1]),
        &mut executor,
        TestClassifier::default(),
    );

    run.result.expect("bounded evidence completes");
    assert_eq!(
        run.events,
        [
            diagnostic("fixture.executor"),
            Event::Probe {
                sequence: 0,
                reply: Some(Answer {
                    responder: responder(1),
                    latency: Duration::from_millis(1),
                    frame: Some(vec![1, 1]),
                }),
            },
            diagnostic("traceroute.evidence_limit"),
            Event::Probe {
                sequence: 1,
                reply: Some(Answer {
                    responder: responder(2),
                    latency: Duration::from_millis(1),
                    frame: None,
                }),
            },
        ]
    );
}

#[test]
fn ties_break_by_rank_then_responder_then_latency_then_bytes() {
    let mut executor = ScriptedExecutor::new([Script {
        responses: vec![
            // A later, slower reply with a higher rank wins.
            (0, &[1, 1], 1),
            (0, &[2, 9], 5),
            // At equal rank the lower responder wins even though it arrives
            // second; first arrival does not decide.
            (1, &[1, 9], 1),
            (1, &[1, 3], 5),
            // At equal rank and responder the shorter latency wins.
            (2, &[1, 3, 2], 5),
            (2, &[1, 3, 9], 1),
            // Then the lower exact bytes win.
            (3, &[1, 3, 9], 1),
            (3, &[1, 3, 2], 1),
            // Uncorrelated responses never win.
            (4, &[0, 1], 1),
        ],
        ..Script::default()
    }]);

    let run = run(
        Workflow::Scan,
        LIMITS,
        Duration::from_secs(10),
        batches(&[5]),
        &mut executor,
        TestClassifier::default(),
    );

    run.result.expect("one bounded batch");
    let reply = |octet, latency, frame: &[u8]| Answer {
        responder: responder(octet),
        latency: Duration::from_millis(latency),
        frame: Some(frame.to_vec()),
    };
    assert_eq!(
        run.events,
        [
            (0, reply(9, 5, &[2, 9])),
            (1, reply(3, 5, &[1, 3])),
            (2, reply(3, 1, &[1, 3, 9])),
            (3, reply(3, 1, &[1, 3, 2])),
        ]
        .map(|(sequence, answer)| Event::Probe {
            sequence,
            reply: Some(answer),
        })
        .into_iter()
        .chain([probe(4)])
        .collect::<Vec<_>>()
    );
}

#[test]
fn undecoded_retention_stops_at_its_limit_with_a_diagnostic_and_keeps_stats() {
    let mut executor = ScriptedExecutor::new([Script {
        undecoded: vec![&[0xff], &[0xfe]],
        diagnostics: vec![Diagnostic::info("fixture.executor", "fixture")],
        ..Script::default()
    }]);
    let limits = EvidenceLimits {
        max_undecoded: 1,
        ..LIMITS
    };

    let run = run(
        Workflow::Scan,
        limits,
        Duration::from_secs(10),
        batches(&[1]),
        &mut executor,
        TestClassifier::default(),
    );

    let stats = run.result.expect("bounded undecoded evidence completes");
    assert_eq!(stats.packets_completed, 1);
    assert_eq!(stats.bytes, 1);
    assert_eq!(
        run.events,
        [
            diagnostic("fixture.executor"),
            probe(0),
            Event::Undecoded(vec![0xff]),
            diagnostic("scan.undecoded_limit"),
        ]
    );
}

#[test]
fn a_terminal_probe_ends_the_operation_after_its_batch() {
    let mut executor = ScriptedExecutor::default();

    let run = run(
        Workflow::Traceroute,
        LIMITS,
        Duration::from_secs(10),
        batches(&[2, 2, 2]),
        &mut executor,
        TestClassifier { terminal: Some(2) },
    );

    run.result.expect("a terminal batch ends the run");
    assert_eq!(executor.executed.len(), 2);
    assert_eq!(run.events, [probe(0), probe(1), probe(2), probe(3)]);
}
