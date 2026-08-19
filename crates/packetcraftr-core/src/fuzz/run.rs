// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use crate::budget::Deadline;
use crate::error::BoundaryError;
use crate::{Packet, field::FieldKind, registry::Registry};

use super::error::Error;
use super::mutation::prepare_with_events;
use super::result::{Event, Stats, Summary};

/// A completely prepared and bounded deterministic mutation campaign.
///
/// Live callers must prepare the campaign before authorization and reuse
/// these exact cases; preparation never performs networking or capture I/O.
#[derive(Clone, Debug)]
pub struct Campaign {
    pub(super) cases: Vec<super::result::Case>,
    pub(super) built_case_count: u64,
    pub(super) built_byte_count: u64,
    pub(super) retained_byte_count: u64,
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
        let prepared = prepare_with_events(request, packet, registry, deadline, &mut |case| {
            cases.push(case);
            Ok(())
        })?;
        Ok(Self {
            cases,
            built_case_count: prepared.built_case_count,
            built_byte_count: prepared.built_byte_count,
            retained_byte_count: prepared.retained_byte_count,
        })
    }

    pub fn cases(&self) -> &[super::result::Case] {
        &self.cases
    }

    pub fn built_case_count(&self) -> u64 {
        self.built_case_count
    }

    pub fn built_byte_count(&self) -> u64 {
        self.built_byte_count
    }

    pub fn retained_byte_count(&self) -> u64 {
        self.retained_byte_count
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
    let summary = run_with_events(request, packet, registry, |event| {
        let Event::Case(case) = event;
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
pub fn run_with_events<F>(
    request: &super::request::Request,
    packet: Packet,
    registry: Arc<Registry>,
    mut emit: F,
) -> Result<Summary, Error>
where
    F: FnMut(Event) -> Result<(), BoundaryError>,
{
    request.validate()?;
    let mut deadline = Deadline::new(request.limits.max_duration);
    let prepared = prepare_with_events(request, packet, registry, &mut deadline, &mut |case| {
        emit(Event::Case(case))
    })?;
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
