// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use crate::budget::Deadline;
use crate::{Packet, registry::Registry};

use super::error::Error;
use super::prepare::prepare_with_events;
use super::report::{Case, Report, Stats, Summary};
use super::request::Request;

/// A completely prepared and bounded deterministic mutation campaign.
///
/// Live callers must prepare the campaign before authorization and reuse
/// these exact cases; preparation never performs networking or capture I/O.
#[derive(Clone, Debug)]
pub struct Campaign {
    pub(super) cases: Vec<Case>,
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
        prepare_with_events(request, packet, registry, deadline, &mut |case, _| {
            cases.push(case);
            Ok(())
        })?;
        Ok(Self { cases })
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
    Ok(Report {
        seed: summary.seed,
        first_case: summary.first_case,
        cases,
        diagnostics: summary.diagnostics,
        stats: summary.stats,
    })
}

/// Generates each deterministic case once and hands it to `emit` as soon as
/// its offline outcome is final.
///
/// `emit` receives the campaign deadline so a publisher can bound how long it
/// waits for backpressure. Its failure aborts later cases.
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
        stats: Stats {
            cases_generated: u64::try_from(request.cases).unwrap_or(u64::MAX),
            cases_built: prepared.built_case_count,
            bytes: prepared.built_byte_count,
            elapsed: prepared.elapsed,
        },
    })
}
