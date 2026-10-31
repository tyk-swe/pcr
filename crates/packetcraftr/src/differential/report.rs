// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::SocketAddr;

use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::frame::Frame;
use serde::{Deserialize, Serialize};

use super::catalog::catalog;
use crate::engine::execution::Shared;
use crate::{Sink, Stats};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    Unanswered,
    Flaky,
    NotRun,
}

impl Verdict {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Unanswered => "unanswered",
            Self::Flaky => "flaky",
            Self::NotRun => "not_run",
        }
    }
}

#[must_use]
pub fn verdict_for(answered: &[bool]) -> Verdict {
    if answered.is_empty() {
        return Verdict::NotRun;
    }
    if answered.iter().all(|value| *value) {
        return Verdict::Accepted;
    }
    if answered.iter().any(|value| *value) {
        return Verdict::Flaky;
    }
    Verdict::Unanswered
}

#[derive(Clone, Debug)]
pub struct AttemptEvidence {
    pub variant_index: usize,
    pub attempt_seq: u32,
    pub answered: bool,
    pub packets_sent: usize,
    pub payload_sha256: [u8; 32],
    pub reply: Option<Frame>,
}

#[derive(Clone, Debug)]
pub struct Row {
    pub variant_index: usize,
    pub verdict: Verdict,
    pub answered: usize,
    pub attempts: usize,
}

#[derive(Clone, Debug)]
pub enum Event {
    Attempt(AttemptEvidence),
    Diagnostic(Diagnostic),
}

#[derive(Clone, Debug)]
pub struct Report {
    pub valid: bool,
    pub provisional: bool,
    pub plan_digest: String,
    pub source_port: u16,
    pub spoof_source: Option<std::net::Ipv4Addr>,
    pub rows: Vec<Row>,
    pub stats: Stats,
}

#[derive(Clone, Debug)]
pub struct Aggregate {
    pub valid: bool,
    pub provisional: bool,
    pub plan_digest: String,
    pub source_port: u16,
    pub spoof_source: Option<std::net::Ipv4Addr>,
    pub attempts: Vec<AttemptEvidence>,
    pub diagnostics: Vec<Diagnostic>,
    pub rows: Vec<Row>,
    pub stats: Stats,
}

pub fn rows_for(attempts: &[AttemptEvidence]) -> Vec<Row> {
    catalog()
        .iter()
        .enumerate()
        .map(|(variant_index, _)| {
            let flags: Vec<bool> = attempts
                .iter()
                .filter(|attempt| attempt.variant_index == variant_index)
                .map(|attempt| attempt.answered)
                .collect();
            Row {
                variant_index,
                verdict: verdict_for(&flags),
                answered: flags.iter().filter(|value| **value).count(),
                attempts: flags.len(),
            }
        })
        .collect()
}

#[derive(Clone, Default)]
pub struct Collector(Shared<Vec<Event>>);

impl Sink<Event> for Collector {
    fn delivery(&self) -> crate::Delivery {
        crate::Delivery::Cooperative
    }

    type Ack = ();

    fn publish(&mut self, event: Event) -> Result<(), BoundaryError> {
        self.0.update(|events| events.push(event));
        Ok(())
    }
}

impl Collector {
    #[must_use]
    pub fn finish(self, report: Report) -> Aggregate {
        let mut attempts = Vec::new();
        let mut diagnostics = Vec::new();
        for event in self.0.take() {
            match event {
                Event::Attempt(attempt) => attempts.push(attempt),
                Event::Diagnostic(diagnostic) => diagnostics.push(diagnostic),
            }
        }
        Aggregate {
            valid: report.valid,
            provisional: report.provisional,
            plan_digest: report.plan_digest,
            source_port: report.source_port,
            spoof_source: report.spoof_source,
            attempts,
            diagnostics,
            rows: report.rows,
            stats: report.stats,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceptionRecord {
    pub variant_index: u16,
    pub attempt_seq: u32,
    pub source: SocketAddr,
    pub payload_sha256: String,
}

#[derive(Clone, Debug)]
pub enum ResponderEvent {
    Received(ReceptionRecord),
}

#[derive(Clone, Debug, Default)]
pub struct ResponderReport {
    pub received: usize,
    pub ignored: usize,
    pub replies_sent: usize,
}

#[derive(Clone, Debug, Default)]
pub struct ResponderAggregate {
    pub records: Vec<ReceptionRecord>,
    pub report: ResponderReport,
}

#[derive(Clone, Default)]
pub struct ResponderCollector(Shared<Vec<ReceptionRecord>>);

impl Sink<ResponderEvent> for ResponderCollector {
    fn delivery(&self) -> crate::Delivery {
        crate::Delivery::Cooperative
    }

    type Ack = ();

    fn publish(&mut self, event: ResponderEvent) -> Result<(), BoundaryError> {
        self.0.update(|records| match event {
            ResponderEvent::Received(record) => records.push(record),
        });
        Ok(())
    }
}

impl ResponderCollector {
    #[must_use]
    pub fn finish(self, report: ResponderReport) -> ResponderAggregate {
        ResponderAggregate {
            records: self.0.take(),
            report,
        }
    }
}

/// Finalizes provisional attempts from Responder reception records. A record
/// only answers an attempt when the variant, attempt sequence, and received
/// payload digest all match what was sent, and, for spoofed Campaigns, the
/// reception source matches the spoofed source tuple that was sent from.
#[must_use]
pub fn join_receptions(mut aggregate: Aggregate, records: &[ReceptionRecord]) -> Aggregate {
    let spoof_source = aggregate.spoof_source;
    let source_port = aggregate.source_port;
    for attempt in &mut aggregate.attempts {
        if attempt.answered {
            continue;
        }
        let expected = hex(&attempt.payload_sha256);
        attempt.answered = records.iter().any(|record| {
            let source_matches = match spoof_source {
                Some(source) => {
                    record.source.ip() == std::net::IpAddr::V4(source)
                        && record.source.port() == source_port
                }
                None => true,
            };
            source_matches
                && usize::from(record.variant_index) == attempt.variant_index
                && record.attempt_seq == attempt.attempt_seq
                && record.payload_sha256 == expected
        });
    }
    aggregate.rows = rows_for(&aggregate.attempts);
    aggregate.valid = aggregate
        .rows
        .first()
        .is_some_and(|row| row.verdict == Verdict::Accepted);
    aggregate.provisional = false;
    aggregate
}

#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt(variant_index: usize, seq: u32, answered: bool) -> AttemptEvidence {
        AttemptEvidence {
            variant_index,
            attempt_seq: seq,
            answered,
            packets_sent: 1,
            payload_sha256: [0x11; 32],
            reply: None,
        }
    }

    #[test]
    fn verdict_aggregation_distinguishes_flaky() {
        assert_eq!(verdict_for(&[true, true]), Verdict::Accepted);
        assert_eq!(verdict_for(&[false, false]), Verdict::Unanswered);
        assert_eq!(verdict_for(&[true, false]), Verdict::Flaky);
        assert_eq!(verdict_for(&[]), Verdict::NotRun);
    }

    #[test]
    fn join_only_answers_on_full_identity_match() {
        let aggregate = Aggregate {
            valid: false,
            provisional: true,
            plan_digest: "digest".to_owned(),
            source_port: 53210,
            spoof_source: None,
            attempts: vec![
                attempt(0, 0, true),
                attempt(1, 1, false),
                attempt(2, 2, false),
            ],
            diagnostics: Vec::new(),
            rows: Vec::new(),
            stats: Stats::default(),
        };
        let records = vec![
            ReceptionRecord {
                variant_index: 1,
                attempt_seq: 1,
                source: "192.0.2.99:53210".parse().expect("addr"),
                payload_sha256: hex(&[0x11; 32]),
            },
            ReceptionRecord {
                variant_index: 2,
                attempt_seq: 2,
                source: "192.0.2.99:53210".parse().expect("addr"),
                payload_sha256: hex(&[0x22; 32]),
            },
        ];
        let joined = join_receptions(aggregate, &records);
        assert!(joined.attempts[1].answered);
        assert!(!joined.attempts[2].answered);
        assert!(!joined.provisional);
        assert!(joined.valid);
    }

    #[test]
    fn spoofed_join_requires_the_spoofed_source_tuple() {
        let spoofed = std::net::Ipv4Addr::new(192, 0, 2, 99);
        let aggregate = Aggregate {
            valid: false,
            provisional: true,
            plan_digest: "digest".to_owned(),
            source_port: 53210,
            spoof_source: Some(spoofed),
            attempts: vec![attempt(0, 0, false), attempt(1, 1, false)],
            diagnostics: Vec::new(),
            rows: Vec::new(),
            stats: Stats::default(),
        };
        let records = vec![
            ReceptionRecord {
                variant_index: 0,
                attempt_seq: 0,
                source: "192.0.2.99:53210".parse().expect("addr"),
                payload_sha256: hex(&[0x11; 32]),
            },
            ReceptionRecord {
                variant_index: 1,
                attempt_seq: 1,
                source: "198.51.100.7:53210".parse().expect("addr"),
                payload_sha256: hex(&[0x11; 32]),
            },
        ];
        let joined = join_receptions(aggregate, &records);
        assert!(joined.attempts[0].answered);
        assert!(!joined.attempts[1].answered);
    }
}
