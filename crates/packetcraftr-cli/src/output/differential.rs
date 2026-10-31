// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use packetcraftr::differential as lib;

use crate::output::contract::Error;
use crate::output::envelope::Published;
use crate::output::frame::Captured;

published_enum! {
    pub enum Verdict from lib::Verdict {
        Accepted => "accepted",
        Unanswered => "unanswered",
        Flaky => "flaky",
        NotRun => "not_run",
    }
}

fn variant_id(index: usize) -> String {
    lib::catalog::catalog().get(index).map_or_else(
        || format!("unknown-{index}"),
        |variant| variant.id.to_owned(),
    )
}

#[derive(Clone, Debug, Serialize)]
pub struct PlanRow {
    pub variant: String,
    pub hypothesis: String,
    pub packets_per_attempt: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct PlanReport {
    pub plan_digest: String,
    pub token: String,
    pub repeats: u64,
    pub rows: Vec<PlanRow>,
    pub total_packets: u64,
    pub total_wire_bytes: u64,
}

impl PlanReport {
    #[must_use]
    pub fn from_summary(summary: lib::PlanSummary, token: &[u8; 16], repeats: u32) -> Self {
        Self {
            plan_digest: summary.digest,
            token: lib::hex(token),
            repeats: u64::from(repeats),
            rows: summary
                .rows
                .into_iter()
                .map(|row| PlanRow {
                    variant: row.id.to_owned(),
                    hypothesis: row.hypothesis.to_owned(),
                    packets_per_attempt: row.packets_per_attempt as u64,
                })
                .collect(),
            total_packets: summary.total_packets,
            total_wire_bytes: summary.total_wire_bytes,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Row {
    pub variant: String,
    pub verdict: Verdict,
    pub answered: u64,
    pub attempts: u64,
}

impl From<lib::Row> for Row {
    fn from(row: lib::Row) -> Self {
        Self {
            variant: variant_id(row.variant_index),
            verdict: row.verdict.into(),
            answered: row.answered as u64,
            attempts: row.attempts as u64,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Attempt {
    pub variant: String,
    pub attempt_seq: u64,
    pub answered: bool,
    pub packets_sent: u64,
    pub payload_sha256: String,
    pub reply: Option<Captured>,
}

impl TryFrom<lib::AttemptEvidence> for Attempt {
    type Error = Error;

    fn try_from(attempt: lib::AttemptEvidence) -> Result<Self, Error> {
        Ok(Self {
            variant: variant_id(attempt.variant_index),
            attempt_seq: u64::from(attempt.attempt_seq),
            answered: attempt.answered,
            packets_sent: attempt.packets_sent as u64,
            payload_sha256: lib::hex(&attempt.payload_sha256),
            reply: attempt.reply.map(Captured::try_from).transpose()?,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub valid: bool,
    pub provisional: bool,
    pub plan_digest: String,
    pub source_port: u64,
    pub spoof_source: Option<String>,
    pub rows: Vec<Row>,
    pub attempts: Vec<Attempt>,
}

impl TryFrom<lib::Aggregate> for Published<Report> {
    type Error = Error;

    fn try_from(aggregate: lib::Aggregate) -> Result<Self, Error> {
        let attempts = aggregate
            .attempts
            .into_iter()
            .map(Attempt::try_from)
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(Self::new(
            Report {
                valid: aggregate.valid,
                provisional: aggregate.provisional,
                plan_digest: aggregate.plan_digest,
                source_port: u64::from(aggregate.source_port),
                spoof_source: aggregate.spoof_source.map(|source| source.to_string()),
                rows: aggregate.rows.into_iter().map(Row::from).collect(),
                attempts,
            },
            aggregate.diagnostics,
        )
        .with_stats(aggregate.stats))
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum Event {
    Attempt {
        variant: String,
        attempt_seq: u64,
        answered: bool,
        packets_sent: u64,
        payload_sha256: String,
        reply: Option<Captured>,
    },
    Diagnostic {},
    Complete {
        valid: bool,
        provisional: bool,
        plan_digest: String,
        rows: Vec<Row>,
    },
}

impl TryFrom<lib::Event> for Published<Event> {
    type Error = Error;

    fn try_from(event: lib::Event) -> Result<Self, Error> {
        let (event, diagnostics) = match event {
            lib::Event::Attempt(attempt) => {
                let attempt = Attempt::try_from(attempt)?;
                (
                    Event::Attempt {
                        variant: attempt.variant,
                        attempt_seq: attempt.attempt_seq,
                        answered: attempt.answered,
                        packets_sent: attempt.packets_sent,
                        payload_sha256: attempt.payload_sha256,
                        reply: attempt.reply,
                    },
                    Vec::new(),
                )
            }
            lib::Event::Diagnostic(diagnostic) => (Event::Diagnostic {}, vec![diagnostic]),
        };
        Ok(Self::new(event, diagnostics))
    }
}

impl From<lib::Report> for Published<Event> {
    fn from(report: lib::Report) -> Self {
        Self::new(
            Event::Complete {
                valid: report.valid,
                provisional: report.provisional,
                plan_digest: report.plan_digest,
                rows: report.rows.into_iter().map(Row::from).collect(),
            },
            Vec::new(),
        )
        .with_stats(report.stats)
    }
}

impl crate::output::stream::StreamRecord for Event {
    fn event_name(&self) -> &'static str {
        match self {
            Self::Attempt { .. } => "attempt",
            Self::Diagnostic {} => "diagnostic",
            Self::Complete { .. } => "complete",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Reception {
    pub variant: String,
    pub attempt_seq: u64,
    pub source: String,
    pub payload_sha256: String,
}

impl From<lib::ReceptionRecord> for Reception {
    fn from(record: lib::ReceptionRecord) -> Self {
        Self {
            variant: variant_id(usize::from(record.variant_index)),
            attempt_seq: u64::from(record.attempt_seq),
            source: record.source.to_string(),
            payload_sha256: record.payload_sha256,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ResponderReport {
    pub received: u64,
    pub ignored: u64,
    pub replies_sent: u64,
    pub records: Vec<Reception>,
}

impl From<lib::ResponderAggregate> for Published<ResponderReport> {
    fn from(aggregate: lib::ResponderAggregate) -> Self {
        Self::new(
            ResponderReport {
                received: aggregate.report.received as u64,
                ignored: aggregate.report.ignored as u64,
                replies_sent: aggregate.report.replies_sent as u64,
                records: aggregate.records.into_iter().map(Reception::from).collect(),
            },
            Vec::new(),
        )
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum ResponderEvent {
    Received {
        variant: String,
        attempt_seq: u64,
        source: String,
        payload_sha256: String,
    },
    Complete {
        received: u64,
        ignored: u64,
        replies_sent: u64,
    },
}

impl From<lib::ResponderEvent> for Published<ResponderEvent> {
    fn from(event: lib::ResponderEvent) -> Self {
        let event = match event {
            lib::ResponderEvent::Received(record) => {
                let record = Reception::from(record);
                ResponderEvent::Received {
                    variant: record.variant,
                    attempt_seq: record.attempt_seq,
                    source: record.source,
                    payload_sha256: record.payload_sha256,
                }
            }
        };
        Self::new(event, Vec::new())
    }
}

impl From<lib::ResponderReport> for Published<ResponderEvent> {
    fn from(report: lib::ResponderReport) -> Self {
        Self::new(
            ResponderEvent::Complete {
                received: report.received as u64,
                ignored: report.ignored as u64,
                replies_sent: report.replies_sent as u64,
            },
            Vec::new(),
        )
    }
}

impl crate::output::stream::StreamRecord for ResponderEvent {
    fn event_name(&self) -> &'static str {
        match self {
            Self::Received { .. } => "received",
            Self::Complete { .. } => "complete",
        }
    }
}
