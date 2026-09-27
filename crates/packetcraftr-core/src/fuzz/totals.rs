// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The coherence check every published campaign passes: its case counts
//! agree with each other and with the cases it published.

use super::report::{Case, CaseOutcome, Report, Stats};

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
/// Checking cases against the counts requires one case per generated case,
/// one non-rejected case per built case, and each case carrying the campaign
/// seed and its index in publication order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Totals {
    pub generated: u64,
    pub built: u64,
    pub rejected: u64,
}

impl Totals {
    /// Counts checked against each other.
    ///
    /// # Errors
    ///
    /// Returns [`IncoherentReport`] when more cases were built than generated.
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

    /// Checks the campaign's published cases, in publication order, against
    /// these counts.
    ///
    /// # Errors
    ///
    /// Returns [`IncoherentReport`] when the cases disagree with the counts,
    /// the campaign seed, or the publication order.
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use bytes::Bytes;

    use crate::fuzz::{Report, Request, Stats, Totals, run};
    use crate::layer::Raw;
    use crate::packet::Packet;
    use crate::protocol::{network::Ipv4, transport::Udp};

    fn report(cases: usize) -> Report {
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                source: Ipv4Addr::new(192, 0, 2, 1),
                destination: Ipv4Addr::new(198, 51, 100, 1),
                ..Ipv4::default()
            })
            .push(Udp {
                destination_port: 9,
                ..Udp::default()
            })
            .push(Raw::new(Bytes::from_static(b"campaign")));
        let request = Request {
            cases,
            ..Request::default()
        };
        run(&request, packet, crate::protocol::builtin::registry())
            .expect("offline fixture campaign runs")
    }

    #[test]
    fn a_coherent_campaign_reports_its_totals() {
        let totals = Totals::try_from(&report(2)).expect("a generated campaign is coherent");
        assert_eq!(totals.generated, 2);
        assert_eq!(totals.built + totals.rejected, 2);
    }

    #[test]
    fn campaign_totals_reject_more_built_than_generated_cases() {
        let stats = Stats {
            cases_generated: 0,
            cases_built: 1,
            ..Stats::default()
        };
        assert_eq!(
            Totals::try_from(&stats)
                .expect_err("the totals are incoherent")
                .to_string(),
            "built case count exceeds generated case count"
        );
    }

    #[test]
    fn campaign_cases_must_match_the_summary_and_publication_order() {
        let mut missing = report(1);
        missing.cases.clear();
        let mut reordered = report(2);
        reordered.cases.swap(0, 1);
        let mut foreign = report(1);
        foreign.cases[0].operation_seed = foreign.seed.wrapping_add(1);
        let mut miscounted = report(1);
        miscounted.stats.cases_built = 1 - miscounted.stats.cases_built;
        for (report, reason) in [
            (
                missing,
                "case cardinality does not match the campaign summary",
            ),
            (
                reordered,
                "case identity or publication order does not match the campaign",
            ),
            (
                foreign,
                "case identity or publication order does not match the campaign",
            ),
            (
                miscounted,
                "case outcomes do not match the campaign built count",
            ),
        ] {
            assert_eq!(
                Totals::try_from(&report)
                    .expect_err("an incoherent campaign is refused")
                    .to_string(),
                reason
            );
        }
    }
}
