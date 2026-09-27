// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use crate::budget::Deadline;
use crate::{packet::Packet, registry::Registry};

use super::error::Error;
use super::prepare::{PreparedCases, prepare_with_events};
use super::report::{Case, Report, Stats, Summary};
use super::request::Request;

/// Live callers must prepare the campaign before authorization and reuse these exact cases.
#[derive(Clone, Debug)]
pub struct Campaign {
    cases: Vec<Case>,
    stats: Stats,
}

impl Campaign {
    pub fn prepare(
        request: &Request,
        packet: Packet,
        registry: Arc<Registry>,
        deadline: &mut Deadline,
    ) -> Result<Self, Error> {
        request.validate()?;
        let mut cases = Vec::with_capacity(request.cases);
        let prepared = prepare_with_events(request, packet, registry, deadline, &mut |case, _| {
            cases.push(case);
            Ok(())
        })?;
        Ok(Self {
            cases,
            stats: campaign_stats(request, &prepared),
        })
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    pub fn into_cases(self) -> Vec<Case> {
        self.cases
    }
}

pub fn run(request: &Request, packet: Packet, registry: Arc<Registry>) -> Result<Report, Error> {
    let mut cases = Vec::new();
    let summary = run_observed(request, packet, registry, |case, _| {
        cases.push(case);
        Ok(())
    })?;
    Ok(Report::from_summary(summary, cases))
}

pub fn run_observed<F>(
    request: &Request,
    packet: Packet,
    registry: Arc<Registry>,
    mut emit: F,
) -> Result<Summary, Error>
where
    F: FnMut(Case, &Deadline) -> Result<(), Error>,
{
    request.validate()?;
    let mut deadline = Deadline::new(request.limits.max_duration);
    let prepared = prepare_with_events(request, packet, registry, &mut deadline, &mut emit)?;
    Ok(Summary {
        seed: request.seed,
        first_case: request.first_case,
        diagnostics: Vec::new(),
        stats: campaign_stats(request, &prepared),
    })
}

fn campaign_stats(request: &Request, prepared: &PreparedCases) -> Stats {
    Stats {
        cases_generated: u64::try_from(request.cases).unwrap_or(u64::MAX),
        cases_built: prepared.built_case_count,
        bytes: prepared.built_byte_count,
        elapsed: prepared.elapsed,
    }
}
