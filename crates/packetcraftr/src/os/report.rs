// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, SystemTime};

use packetcraftr_core::{diagnostic::Diagnostic, error::BoundaryError, frame::Frame};

use super::{Error, Match, Observation, Probe};
use crate::{Sink, Stats, execution::Shared};

#[derive(Clone, Debug)]
pub struct ProbeEvidence {
    pub sequence: u64,
    pub probe: Option<Probe>,
    pub attempt: u32,
    pub sent: Frame,
    pub response: Option<Frame>,
    pub observation: Option<Observation>,
    pub received_at: Option<SystemTime>,
    pub latency: Option<Duration>,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub enum Event {
    Preparation(super::executor::Preparation),
    Probe(ProbeEvidence),
    Additional {
        sequence: u64,
        observation: Option<Observation>,
        frame: Frame,
        reason: String,
    },
    Undecoded(Frame),
    Diagnostic(Diagnostic),
}

#[derive(Clone, Debug)]
pub struct Report {
    pub target: crate::target::Target,
    pub probe_set: &'static str,
    pub corpus: String,
    pub corpus_version: String,
    pub identification: Match,
    pub observations: Vec<Observation>,
    pub retained_evidence_bytes: usize,
    pub complete: bool,
    pub stats: Stats,
}

#[derive(Clone, Debug)]
pub struct Aggregate {
    pub report: Report,
    pub events: Vec<Event>,
}

#[derive(Clone, Default)]
pub struct Collector(pub(super) Shared<Vec<Event>>);

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
    pub fn finish(self, report: Report) -> Result<Aggregate, Error> {
        let events = self.0.take();
        let count = events
            .iter()
            .filter(|event| matches!(event, Event::Probe(_)))
            .count();
        let ancillary: u64 = events
            .iter()
            .filter_map(|event| match event {
                Event::Preparation(preparation) => Some(preparation.stats.packets_completed),
                _ => None,
            })
            .sum();
        if count as u64 + ancillary != report.stats.packets_completed {
            return Err(Error::Evidence {
                sequence: 0,
                message: "collected probes disagree with completed transmissions".into(),
            });
        }
        Ok(Aggregate { report, events })
    }

    pub(super) fn observations(&self) -> Vec<Observation> {
        self.0.update(|events| {
            events
                .iter()
                .filter_map(|event| match event {
                    Event::Probe(probe) => probe.observation.clone(),
                    Event::Additional { observation, .. } => observation.clone(),
                    _ => None,
                })
                .collect()
        })
    }

    pub(super) fn incomplete(&self) -> bool {
        self.0.update(|events| {
            events.iter().any(|event| match event {
                Event::Diagnostic(diagnostic) => {
                    diagnostic.code.contains("limit") || diagnostic.code.contains("incomplete")
                }
                Event::Probe(probe) => probe.latency.is_some() && probe.response.is_none(),
                _ => false,
            })
        })
    }
}
