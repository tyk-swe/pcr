// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::{frame::Frame, fuzz as packet_fuzz};
use packetcraftr_netio::capture::Stats as CaptureStats;
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseOutcome {
    Built,
    Rejected,
    Response,
    Timeout,
}

impl CaseOutcome {
    /// The serialized name, for text output that must agree with JSON.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::Rejected => "rejected",
            Self::Response => "response",
            Self::Timeout => "timeout",
        }
    }
}

impl std::fmt::Display for CaseOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug)]
pub struct Case {
    pub prepared: packet_fuzz::Case,
    pub outcome: CaseOutcome,
    pub sent: Option<Frame>,
    pub responses: Vec<Frame>,
    pub unmatched: Vec<Frame>,
    pub undecoded: Vec<Frame>,
}

impl From<packet_fuzz::CaseOutcome> for CaseOutcome {
    /// An offline case has been generated and either built or rejected; the
    /// live outcomes are reached only after transmission.
    fn from(value: packet_fuzz::CaseOutcome) -> Self {
        match value {
            packet_fuzz::CaseOutcome::Built => Self::Built,
            packet_fuzz::CaseOutcome::Rejected => Self::Rejected,
        }
    }
}

impl From<packet_fuzz::Case> for Case {
    fn from(prepared: packet_fuzz::Case) -> Self {
        let outcome = prepared.outcome.into();
        Self {
            prepared,
            outcome,
            sent: None,
            responses: Vec::new(),
            unmatched: Vec::new(),
            undecoded: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub cases_generated: u64,
    pub cases_built: u64,
    pub packets_attempted: u64,
    pub packets_completed: u64,
    pub bytes: u64,
    pub elapsed: Duration,
    pub capture: CaptureStats,
}

/// One completed live campaign. Diagnostics are carried by the case they were
/// raised during, in [`Case::prepared`]'s `diagnostics`, so the campaign does
/// not repeat them.
#[derive(Clone, Debug)]
pub struct Report {
    pub seed: u64,
    pub first_case: u64,
    pub cases: Vec<Case>,
    pub stats: Stats,
}

/// Final live campaign metadata after every case event was published.
#[derive(Clone, Debug)]
pub struct Summary {
    pub seed: u64,
    pub first_case: u64,
    pub stats: Stats,
}

/// Why a campaign's cases disagree with its own summary.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct IncoherentReport {
    reason: &'static str,
}

impl IncoherentReport {
    const fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

/// A campaign's case counts, established as coherent: built cases never
/// exceed generated cases, and every case was either built or rejected.
///
/// Converting a report also checks its cases against the counts: one case
/// per generated case, one non-rejected case per built case, and each case
/// carrying the campaign seed and its index in publication order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Totals {
    pub generated: u64,
    pub built: u64,
    pub rejected: u64,
}

impl Totals {
    /// Counts checked against each other.
    pub fn new(generated: u64, built: u64) -> Result<Self, IncoherentReport> {
        let rejected = generated.checked_sub(built).ok_or(IncoherentReport::new(
            "built case count exceeds generated case count",
        ))?;
        Ok(Self {
            generated,
            built,
            rejected,
        })
    }

    /// Checks the published cases, in order, against these counts.
    fn check_cases<'a>(
        self,
        seed: u64,
        first_case: u64,
        cases: impl ExactSizeIterator<Item = (&'a packet_fuzz::Case, bool)>,
    ) -> Result<Self, IncoherentReport> {
        if u64::try_from(cases.len()).unwrap_or(u64::MAX) != self.generated {
            return Err(IncoherentReport::new(
                "case cardinality does not match the campaign summary",
            ));
        }
        let mut built = 0_u64;
        let mut identities = Vec::with_capacity(cases.len());
        for (case, was_built) in cases {
            built = built.saturating_add(u64::from(was_built));
            identities.push((case.index, case.operation_seed));
        }
        if built != self.built {
            return Err(IncoherentReport::new(
                "case outcomes do not match the campaign built count",
            ));
        }
        for (offset, (index, operation_seed)) in identities.into_iter().enumerate() {
            let expected = first_case
                .checked_add(u64::try_from(offset).unwrap_or(u64::MAX))
                .ok_or(IncoherentReport::new("case index order overflowed"))?;
            if index != expected || operation_seed != seed {
                return Err(IncoherentReport::new(
                    "case identity or publication order does not match the campaign",
                ));
            }
        }
        Ok(self)
    }
}

impl TryFrom<&Stats> for Totals {
    type Error = IncoherentReport;

    fn try_from(stats: &Stats) -> Result<Self, IncoherentReport> {
        Self::new(stats.cases_generated, stats.cases_built)
    }
}

impl TryFrom<&packet_fuzz::Stats> for Totals {
    type Error = IncoherentReport;

    fn try_from(stats: &packet_fuzz::Stats) -> Result<Self, IncoherentReport> {
        Self::new(stats.cases_generated, stats.cases_built)
    }
}

impl TryFrom<&Report> for Totals {
    type Error = IncoherentReport;

    fn try_from(report: &Report) -> Result<Self, IncoherentReport> {
        Self::try_from(&report.stats)?.check_cases(
            report.seed,
            report.first_case,
            report
                .cases
                .iter()
                .map(|case| (&case.prepared, case.outcome != CaseOutcome::Rejected)),
        )
    }
}

impl TryFrom<&packet_fuzz::Report> for Totals {
    type Error = IncoherentReport;

    fn try_from(report: &packet_fuzz::Report) -> Result<Self, IncoherentReport> {
        Self::try_from(&report.stats)?.check_cases(
            report.seed,
            report.first_case,
            report
                .cases
                .iter()
                .map(|case| (case, case.outcome != packet_fuzz::CaseOutcome::Rejected)),
        )
    }
}
