// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::{frame::Frame, fuzz as packet_fuzz};

use crate::execution::Shared;
use crate::{Sink, Stats};
use packetcraftr_core::error::BoundaryError;

/// What became of one transmitted case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// At least one correlated response arrived within the case's window.
    Response,
    /// The window closed with no correlated response.
    Timeout,
}

/// What one transmitted case produced: the exact frame sent and the frames
/// retained under the campaign-wide evidence budget.
///
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

/// One campaign case as the live run finished it.
///
/// `case` is the case core prepared. Once it was transmitted, its `built`
/// and `decoded` packets are the ones actually sent on the case's route, and
/// its diagnostics include those raised while sending and collecting. A
/// rejected case is never sent and has no evidence.
#[derive(Clone, Debug)]
pub struct Trial {
    pub case: packet_fuzz::Case,
    pub evidence: Option<Evidence>,
}

/// What a live campaign publishes while it runs, in case order. Each event
/// is answered before the next case is sent.
#[derive(Clone, Debug)]
pub enum Event {
    /// A case whose live outcome is final.
    Case(Trial),
}

/// The terminal result of one live campaign.
///
/// Diagnostics are carried by the case they were raised during, in its
/// [`Trial::case`], so the campaign does not repeat them.
#[derive(Clone, Debug)]
pub struct Report {
    pub seed: u64,
    pub first_case: u64,
    /// What the campaign generated and built before any case was sent, and
    /// how long preparing it took.
    pub campaign: packet_fuzz::Stats,
    /// The live traffic, including every pacing delay.
    pub stats: Stats,
}

/// Every case of one live campaign, in case order, with its terminal report.
///
/// [`Totals::try_from`](packet_fuzz::Totals) checks that the cases agree with
/// the report.
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

/// A sink that keeps every published case. Pass a clone to
/// [`Client::fuzz`](crate::Client::fuzz) and [`finish`](Self::finish) the one
/// kept with the report the campaign returns.
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
    /// Joins the collected cases with the campaign's terminal `report`.
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
