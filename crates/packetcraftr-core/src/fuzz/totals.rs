// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::report::{Case, CaseOutcome, Report, Stats};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Totals {
    pub generated: u64,
    pub built: u64,
    pub rejected: u64,
}

impl Totals {
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

    pub fn check_cases<'a>(
        self,
        seed: u64,
        first_case: u64,
        cases: impl ExactSizeIterator<Item = &'a Case>,
    ) -> Result<Self, IncoherentReport> {
        if u64::try_from(cases.len()).unwrap_or(u64::MAX) != self.generated {
            return Err(IncoherentReport::new(
                "case cardinality does not match the campaign summary",
            ));
        }
        let mut built = 0_u64;
        let mut identities = Vec::with_capacity(cases.len());
        for case in cases {
            built = built.saturating_add(u64::from(case.outcome != CaseOutcome::Rejected));
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

impl TryFrom<&Report> for Totals {
    type Error = IncoherentReport;

    fn try_from(report: &Report) -> Result<Self, IncoherentReport> {
        Self::try_from(&report.stats)?.check_cases(
            report.seed,
            report.first_case,
            report.cases.iter(),
        )
    }
}
