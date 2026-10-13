// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use super::{
    contract::Error,
    envelope::Published,
    frame::{Captured, Timestamp},
    hex::compact_hex,
};
use packetcraftr::os as library;

#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    pub target: String,
    pub probe_set: &'static str,
    pub corpus: String,
    pub corpus_version: String,
    pub identification: library::Match,
    pub observations: Vec<library::Observation>,
    pub retained_evidence_bytes: usize,
    pub complete: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    #[serde(flatten)]
    pub summary: Summary,
    pub evidence: Vec<Event>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    Preparation {
        interface: Option<String>,
        target: Option<std::net::IpAddr>,
        request_hex: Option<String>,
        packets_attempted: u64,
        bytes: u64,
        captured: Vec<Captured>,
    },
    Probe {
        sequence: u64,
        probe: Option<library::Probe>,
        attempt: u32,
        sent: Captured,
        response: Option<Captured>,
        observation: Option<library::Observation>,
        received_at: Option<Timestamp>,
        latency: Option<std::time::Duration>,
        reason: String,
    },
    Additional {
        sequence: u64,
        observation: Option<library::Observation>,
        frame: Captured,
        reason: String,
    },
    Undecoded {
        frame: Captured,
    },
    Diagnostic {},
    Complete {
        #[serde(flatten)]
        summary: Summary,
    },
}

impl super::stream::StreamRecord for Event {
    fn event_name(&self) -> &'static str {
        match self {
            Self::Preparation { .. } => "os_preparation",
            Self::Probe { .. } => "os_probe",
            Self::Additional { .. } => "os_additional",
            Self::Undecoded { .. } => "os_undecoded",
            Self::Diagnostic { .. } => "diagnostic",
            Self::Complete { .. } => "complete",
        }
    }
}

fn summary(report: library::Report) -> Summary {
    Summary {
        target: report.target.to_string(),
        probe_set: report.probe_set,
        corpus: report.corpus,
        corpus_version: report.corpus_version,
        identification: report.identification,
        observations: report.observations,
        retained_evidence_bytes: report.retained_evidence_bytes,
        complete: report.complete,
    }
}

impl TryFrom<library::Event> for Published<Event> {
    type Error = Error;
    fn try_from(event: library::Event) -> Result<Self, Error> {
        let value = match event {
            library::Event::Preparation(preparation) => Event::Preparation {
                interface: preparation.interface.map(|interface| interface.name),
                target: preparation.target,
                request_hex: preparation.request_bytes.map(|bytes| compact_hex(&bytes)),
                packets_attempted: preparation.stats.packets_attempted,
                bytes: preparation.stats.bytes,
                captured: preparation
                    .captured
                    .into_iter()
                    .map(Captured::try_from)
                    .collect::<Result<_, _>>()?,
            },
            library::Event::Probe(probe) => Event::Probe {
                sequence: probe.sequence,
                probe: probe.probe,
                attempt: probe.attempt,
                sent: probe.sent.try_into()?,
                response: probe.response.map(Captured::try_from).transpose()?,
                observation: probe.observation,
                received_at: probe.received_at.map(Timestamp::try_from).transpose()?,
                latency: probe.latency,
                reason: probe.reason,
            },
            library::Event::Additional {
                sequence,
                observation,
                frame,
                reason,
            } => Event::Additional {
                sequence,
                observation,
                frame: frame.try_into()?,
                reason,
            },
            library::Event::Undecoded(frame) => Event::Undecoded {
                frame: frame.try_into()?,
            },
            library::Event::Diagnostic(diagnostic) => {
                return Ok(Self::new(Event::Diagnostic {}, vec![diagnostic]));
            }
        };
        Ok(Self::new(value, Vec::new()))
    }
}

impl From<library::Report> for Published<Event> {
    fn from(report: library::Report) -> Self {
        let stats = report.stats.clone();
        Self::new(
            Event::Complete {
                summary: summary(report),
            },
            Vec::new(),
        )
        .with_stats(stats)
    }
}

impl TryFrom<library::Aggregate> for Published<Report> {
    type Error = Error;
    fn try_from(aggregate: library::Aggregate) -> Result<Self, Error> {
        let stats = aggregate.report.stats.clone();
        let mut diagnostics = Vec::new();
        let mut evidence = Vec::new();
        for event in aggregate.events {
            let event = Published::<Event>::try_from(event)?;
            diagnostics.extend(event.diagnostics);
            if !matches!(event.result, Event::Diagnostic {}) {
                evidence.push(event.result);
            }
        }
        Ok(Self::new(
            Report {
                summary: summary(aggregate.report),
                evidence,
            },
            diagnostics,
        )
        .with_stats(stats))
    }
}
