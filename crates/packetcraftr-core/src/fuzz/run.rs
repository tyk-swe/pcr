// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use crate::budget::Deadline;
use crate::error::BoundaryError;
use crate::{Packet, field::FieldKind, registry::Registry};

use super::error::{Error, duration_limit};
use super::mutation::prepare_with_events;
use super::result::{Case, Stats, Summary};

/// A completely prepared and bounded deterministic mutation campaign.
///
/// Live callers must prepare the campaign before authorization and reuse
/// these exact cases; preparation never performs networking or capture I/O.
#[derive(Clone, Debug)]
pub struct Campaign {
    pub(super) cases: Vec<super::result::Case>,
}

impl Campaign {
    pub fn prepare(
        request: &super::request::Request,
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

    pub fn into_cases(self) -> Vec<super::result::Case> {
        self.cases
    }
}

pub fn run(
    request: &super::request::Request,
    packet: Packet,
    registry: Arc<Registry>,
) -> Result<super::result::Result, Error> {
    let mut cases = Vec::new();
    let summary = run_observed(request, packet, registry, |case, _| {
        cases.push(case);
        Ok(())
    })?;
    Ok(super::result::Result {
        seed: summary.seed,
        first_case: summary.first_case,
        cases,
        diagnostics: summary.diagnostics,
        stats: summary.stats,
    })
}

/// Generates each deterministic case once and publishes it as soon as its
/// offline outcome is final.
///
/// The callback runs on a process-budgeted worker. Each result is acknowledged
/// before generation continues, callback failure aborts later cases, and the
/// deadline bounds publisher waiting for callback backpressure. It does not
/// terminate callback code: a callback may finish after this function returns
/// and holds one process-wide worker permit until then.
pub fn run_with_events<F>(
    request: &super::request::Request,
    packet: Packet,
    registry: Arc<Registry>,
    emit: F,
) -> Result<Summary, Error>
where
    F: FnMut(Case) -> Result<(), BoundaryError> + Send + 'static,
{
    let sink = crate::progress::Sink::new(emit).map_err(|source| Error::Output { source })?;
    run_observed(
        request,
        packet,
        registry,
        move |case, deadline| match sink.emit(case, deadline) {
            Ok(()) => Ok(()),
            Err(crate::progress::EmitError::Deadline(error)) => Err(duration_limit(error)),
            Err(crate::progress::EmitError::Output(source)) => Err(Error::Output { source }),
        },
    )
}

fn run_observed<F>(
    request: &super::request::Request,
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
            cases_generated: request.cases as u64,
            cases_built: prepared.built_case_count,
            packets_attempted: request.cases as u64,
            packets_completed: prepared.built_case_count,
            bytes: prepared.built_byte_count,
            ..Stats::default()
        },
    })
}

#[derive(Clone)]
pub(super) struct ResolvedField {
    pub(super) target: super::request::Target,
    pub(super) protocol: String,
    pub(super) kind: FieldKind,
    pub(super) is_derived: bool,
}
