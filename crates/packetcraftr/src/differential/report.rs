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
    Rewritten,
}

impl Verdict {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Unanswered => "unanswered",
            Self::Flaky => "flaky",
            Self::NotRun => "not_run",
            Self::Rewritten => "rewritten",
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
    pub rewritten: bool,
    pub packets_sent: usize,
    pub payload_sha256: [u8; 32],
    pub reply: Option<Frame>,
}

#[derive(Clone, Debug)]
pub struct Row {
    pub variant_index: usize,
    pub verdict: Verdict,
    pub answered: usize,
    pub rewritten: usize,
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
            let mine: Vec<&AttemptEvidence> = attempts
                .iter()
                .filter(|attempt| attempt.variant_index == variant_index)
                .collect();
            let answered = mine.iter().filter(|attempt| attempt.answered).count();
            let rewritten = mine
                .iter()
                .filter(|attempt| attempt.rewritten && !attempt.answered)
                .count();
            let verdict = if mine.is_empty() {
                Verdict::NotRun
            } else if answered == mine.len() {
                Verdict::Accepted
            } else if rewritten == mine.len() {
                Verdict::Rewritten
            } else if answered + rewritten > 0 {
                Verdict::Flaky
            } else {
                Verdict::Unanswered
            };
            Row {
                variant_index,
                verdict,
                answered,
                rewritten,
                attempts: mine.len(),
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
            records: self.into_records(),
            report,
        }
    }

    /// The records received so far, for a run that ended without a report.
    #[must_use]
    pub fn into_records(self) -> Vec<ReceptionRecord> {
        self.0.take()
    }
}

/// Finalizes provisional attempts from Responder reception records. A record
/// only answers an attempt when the variant, attempt sequence, and received
/// payload digest all match what was sent, and, for spoofed Campaigns, the
/// reception source matches the spoofed source tuple that was sent from. A
/// spoofed attempt whose identity matches under a different source tuple is
/// proven rewritten in transit, because the Responder received the exact
/// payload from a source the sender did not use. Unspoofed Campaigns record
/// no sent source, so a rewrite cannot be proven for them here.
#[must_use]
pub fn join_receptions(mut aggregate: Aggregate, records: &[ReceptionRecord]) -> Aggregate {
    let expected_source = aggregate
        .spoof_source
        .map(|source| SocketAddr::from((source, aggregate.source_port)));
    let identities: std::collections::HashSet<(u16, u32, String, Option<SocketAddr>)> = records
        .iter()
        .map(|record| {
            (
                record.variant_index,
                record.attempt_seq,
                record.payload_sha256.clone(),
                expected_source.map(|_| record.source),
            )
        })
        .collect();
    let received: std::collections::HashSet<(u16, u32, String)> = records
        .iter()
        .map(|record| {
            (
                record.variant_index,
                record.attempt_seq,
                record.payload_sha256.clone(),
            )
        })
        .collect();
    for attempt in &mut aggregate.attempts {
        if attempt.answered {
            attempt.rewritten = false;
            continue;
        }
        let Ok(variant_index) = u16::try_from(attempt.variant_index) else {
            continue;
        };
        let digest = hex(&attempt.payload_sha256);
        let key = (
            variant_index,
            attempt.attempt_seq,
            digest.clone(),
            expected_source,
        );
        attempt.answered = identities.contains(&key);
        if attempt.answered {
            attempt.rewritten = false;
        }
        if !attempt.answered
            && expected_source.is_some()
            && received.contains(&(variant_index, attempt.attempt_seq, digest))
        {
            attempt.rewritten = true;
        }
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
    packetcraftr_core::field::hex::compact_hex(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatBehavior {
    NoReceptions,
    Preserved,
    StableTuple,
    StableAddressVaryingPort,
    VaryingAddress,
}

impl NatBehavior {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoReceptions => "no_receptions",
            Self::Preserved => "preserved",
            Self::StableTuple => "stable_tuple",
            Self::StableAddressVaryingPort => "stable_address_varying_port",
            Self::VaryingAddress => "varying_address",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NatMapping {
    pub records: usize,
    pub sources: Vec<std::net::SocketAddr>,
    pub behavior: NatBehavior,
}

/// Classify source-tuple stability from Responder reception records. This
/// observes one destination only: stable here does not prove endpoint
/// independent mapping to other destinations.
#[must_use]
pub fn nat_mapping(
    records: &[ReceptionRecord],
    expected_source: Option<std::net::SocketAddr>,
) -> NatMapping {
    let sources: Vec<std::net::SocketAddr> = records
        .iter()
        .map(|record| record.source)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let behavior = if sources.is_empty() {
        NatBehavior::NoReceptions
    } else if expected_source.is_some_and(|expected| sources == [expected]) {
        NatBehavior::Preserved
    } else if sources.len() == 1 {
        NatBehavior::StableTuple
    } else if sources.iter().all(|source| source.ip() == sources[0].ip()) {
        NatBehavior::StableAddressVaryingPort
    } else {
        NatBehavior::VaryingAddress
    };
    NatMapping {
        records: records.len(),
        sources,
        behavior,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SensorObservation {
    pub variant_index: u16,
    pub attempt_seq: u32,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub payload_sha256: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VantageRow {
    pub variant_index: usize,
    pub attempts: usize,
    pub delivered_and_seen: usize,
    pub delivered_not_seen: usize,
    pub seen_not_delivered: usize,
    pub neither: usize,
    pub rewritten_and_seen: usize,
    pub rewritten_not_seen: usize,
}

/// Classifies joined attempts by both Responder delivery and sensor-probe
/// observation. A sensor observation only counts when its Variant, attempt
/// sequence and exact payload digest match the attempt and its source tuple
/// matches the Campaign source port and spoofed source when one was planned.
/// `Delivered` means the Responder answered; rewritten attempts are kept
/// separate because the exact payload arrived under a different source tuple.
#[must_use]
pub fn three_vantage(aggregate: &Aggregate, sensor: &[SensorObservation]) -> Vec<VantageRow> {
    let seen: std::collections::HashSet<(u16, u32, &str)> = sensor
        .iter()
        .filter(|observation| {
            observation.source.port() == aggregate.source_port
                && aggregate
                    .spoof_source
                    .is_none_or(|source| observation.source.ip() == std::net::IpAddr::V4(source))
        })
        .map(|observation| {
            (
                observation.variant_index,
                observation.attempt_seq,
                observation.payload_sha256.as_str(),
            )
        })
        .collect();
    catalog()
        .iter()
        .enumerate()
        .map(|(variant_index, _)| {
            let mut row = VantageRow {
                variant_index,
                ..VantageRow::default()
            };
            for attempt in aggregate
                .attempts
                .iter()
                .filter(|attempt| attempt.variant_index == variant_index)
            {
                row.attempts += 1;
                let Ok(index) = u16::try_from(attempt.variant_index) else {
                    row.neither += 1;
                    continue;
                };
                let digest = hex(&attempt.payload_sha256);
                let seen = seen.contains(&(index, attempt.attempt_seq, digest.as_str()));
                match (attempt.answered, attempt.rewritten, seen) {
                    (true, _, true) => row.delivered_and_seen += 1,
                    (true, _, false) => row.delivered_not_seen += 1,
                    (false, true, true) => row.rewritten_and_seen += 1,
                    (false, true, false) => row.rewritten_not_seen += 1,
                    (false, false, true) => row.seen_not_delivered += 1,
                    (false, false, false) => row.neither += 1,
                }
            }
            row
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt(variant_index: usize, seq: u32, answered: bool) -> AttemptEvidence {
        AttemptEvidence {
            variant_index,
            attempt_seq: seq,
            answered,
            rewritten: false,
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
    fn join_requires_full_identity_match() {
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
    fn spoofed_join_requires_source_tuple() {
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

    #[test]
    fn nat_mapping_classifies_tuple_stability() {
        let record = |source: &str| ReceptionRecord {
            variant_index: 0,
            attempt_seq: 0,
            source: source.parse().unwrap(),
            payload_sha256: "00".repeat(32),
        };
        let preserved = nat_mapping(
            &[record("192.0.2.1:53210")],
            Some("192.0.2.1:53210".parse().unwrap()),
        );
        assert_eq!(preserved.behavior, NatBehavior::Preserved);
        let varying_port = nat_mapping(&[record("192.0.2.1:1000"), record("192.0.2.1:1001")], None);
        assert_eq!(varying_port.behavior, NatBehavior::StableAddressVaryingPort);
        let varying_ip = nat_mapping(&[record("192.0.2.1:1000"), record("192.0.2.2:1000")], None);
        assert_eq!(varying_ip.behavior, NatBehavior::VaryingAddress);
        assert_eq!(nat_mapping(&[], None).behavior, NatBehavior::NoReceptions);
    }

    #[test]
    fn three_vantage_separates_delivery_rewrite_and_sensor_visibility() {
        let mut rewritten = attempt(1, 4, false);
        rewritten.rewritten = true;
        let mut rewritten_seen = attempt(1, 5, false);
        rewritten_seen.rewritten = true;
        let aggregate = Aggregate {
            valid: true,
            provisional: false,
            plan_digest: "digest".to_owned(),
            source_port: 53210,
            spoof_source: None,
            attempts: vec![
                attempt(0, 0, true),
                attempt(0, 1, true),
                attempt(0, 2, false),
                attempt(0, 3, false),
                rewritten,
                rewritten_seen,
            ],
            diagnostics: Vec::new(),
            rows: Vec::new(),
            stats: Stats::default(),
        };
        let digest = hex(&[0x11; 32]);
        let sensor =
            |variant_index: u16, attempt_seq: u32, payload_sha256: String| SensorObservation {
                variant_index,
                attempt_seq,
                source: "192.0.2.10:53210".parse().unwrap(),
                destination: "198.51.100.20:40101".parse().unwrap(),
                payload_sha256,
            };
        let mut wrong_source_port = sensor(0, 1, digest.clone());
        wrong_source_port.source.set_port(40000);
        let rows = three_vantage(
            &aggregate,
            &[
                sensor(0, 0, digest.clone()),
                wrong_source_port,
                sensor(0, 2, digest.clone()),
                sensor(1, 5, digest.clone()),
                sensor(0, 3, hex(&[0x22; 32])),
            ],
        );
        assert_eq!(rows[0].delivered_and_seen, 1);
        assert_eq!(rows[0].delivered_not_seen, 1);
        assert_eq!(rows[0].seen_not_delivered, 1);
        assert_eq!(rows[0].neither, 1);
        assert_eq!(rows[1].rewritten_not_seen, 1);
        assert_eq!(rows[1].rewritten_and_seen, 1);
        assert_eq!(rows[0].attempts + rows[1].attempts, 6);
    }

    #[test]
    fn spoofed_attempt_received_from_another_source_is_rewritten() {
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
                source: "198.51.100.7:40000".parse().expect("addr"),
                payload_sha256: hex(&[0x11; 32]),
            },
        ];
        let joined = join_receptions(aggregate, &records);
        assert!(joined.attempts[0].answered && !joined.attempts[0].rewritten);
        assert!(!joined.attempts[1].answered && joined.attempts[1].rewritten);
        assert_eq!(joined.rows[0].verdict, Verdict::Accepted);
        assert_eq!(joined.rows[1].verdict, Verdict::Rewritten);
        assert_eq!(joined.rows[1].rewritten, 1);
        assert!(joined.valid);

        let mut rejoined = joined;
        rejoined.attempts[1].answered = false;
        let declared = vec![ReceptionRecord {
            variant_index: 1,
            attempt_seq: 1,
            source: "192.0.2.99:53210".parse().expect("addr"),
            payload_sha256: hex(&[0x11; 32]),
        }];
        let rejoined = join_receptions(rejoined, &declared);
        assert!(rejoined.attempts[1].answered);
        assert!(!rejoined.attempts[1].rewritten);
    }
}
