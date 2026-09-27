// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::{frame::Frame, fuzz as packet_fuzz};

use crate::execution::Shared;
use crate::{Sink, Stats};
use packetcraftr_core::error::BoundaryError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Response,
    Timeout,
}

/// The outcome is decided before retention, so a case that was answered
/// after the budget ran out is still a [`Outcome::Response`] with no
/// retained response.
#[derive(Clone, Debug)]
pub struct Evidence {
    pub sent: Frame,
    pub outcome: Outcome,
    pub responses: Vec<Frame>,
    pub unmatched: Vec<Frame>,
    pub undecoded: Vec<Frame>,
}

#[derive(Clone, Debug)]
pub struct Trial {
    pub case: packet_fuzz::Case,
    pub evidence: Option<Evidence>,
}

#[derive(Clone, Debug)]
pub enum Event {
    Case(Trial),
}

#[derive(Clone, Debug)]
pub struct Report {
    pub seed: u64,
    pub first_case: u64,
    pub campaign: packet_fuzz::Stats,
    pub stats: Stats,
}

#[derive(Clone, Debug)]
pub struct Aggregate {
    pub seed: u64,
    pub first_case: u64,
    pub trials: Vec<Trial>,
    pub campaign: packet_fuzz::Stats,
    pub stats: Stats,
}

impl TryFrom<&Aggregate> for packet_fuzz::Totals {
    type Error = packet_fuzz::IncoherentReport;

    fn try_from(aggregate: &Aggregate) -> Result<Self, packet_fuzz::IncoherentReport> {
        Self::try_from(&aggregate.campaign)?.check_cases(
            aggregate.seed,
            aggregate.first_case,
            aggregate.trials.iter().map(|trial| &trial.case),
        )
    }
}

#[derive(Clone, Default)]
pub struct Collector(Shared<Vec<Trial>>);

impl Sink<Event> for Collector {
    type Ack = ();

    fn publish(&mut self, event: Event) -> Result<(), BoundaryError> {
        self.0.update(|trials| match event {
            Event::Case(trial) => trials.push(trial),
        });
        Ok(())
    }
}

impl Collector {
    #[must_use]
    pub fn finish(self, report: Report) -> Aggregate {
        Aggregate {
            seed: report.seed,
            first_case: report.first_case,
            trials: self.0.take(),
            campaign: report.campaign,
            stats: report.stats,
        }
    }
}
