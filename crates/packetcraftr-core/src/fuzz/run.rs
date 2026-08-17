// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use crate::budget::Deadline;
use crate::{Packet, field::FieldKind, registry::Registry};

use super::error::Error;
use super::mutation::prepare;
use super::request::{Request as FuzzRequest, Target as FuzzTarget};
use super::result::{Case as FuzzCase, Result as FuzzResult, Stats as FuzzStats};

/// A completely prepared and bounded deterministic mutation campaign.
///
/// Live callers must prepare the campaign before authorization and reuse
/// these exact cases; preparation never performs networking or capture I/O.
#[derive(Clone, Debug)]
pub struct Campaign {
    pub(super) cases: Vec<FuzzCase>,
    pub(super) built_case_count: u64,
    pub(super) built_byte_count: u64,
    pub(super) retained_byte_count: u64,
}

impl Campaign {
    pub fn prepare(
        request: &FuzzRequest,
        packet: Packet,
        registry: Arc<Registry>,
        deadline: &mut Deadline,
    ) -> Result<Self, Error> {
        request.validate()?;
        prepare(request, packet, registry, deadline)
    }

    pub fn cases(&self) -> &[FuzzCase] {
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

    pub fn into_cases(self) -> Vec<FuzzCase> {
        self.cases
    }
}

pub fn run(
    request: &FuzzRequest,
    packet: Packet,
    registry: Arc<Registry>,
) -> Result<FuzzResult, Error> {
    let mut deadline = Deadline::new(request.limits.max_duration);
    let campaign = Campaign::prepare(request, packet, registry, &mut deadline)?;
    Ok(FuzzResult {
        seed: request.seed,
        first_case: request.first_case,
        cases: campaign.cases,
        diagnostics: Vec::new(),
        stats: FuzzStats {
            cases_generated: request.cases as u64,
            cases_built: campaign.built_case_count,
            packets_attempted: request.cases as u64,
            packets_completed: campaign.built_case_count,
            bytes: campaign.built_byte_count,
            ..FuzzStats::default()
        },
    })
}

#[derive(Clone)]
pub(super) struct ResolvedField {
    pub(super) target: FuzzTarget,
    pub(super) protocol: String,
    pub(super) kind: FieldKind,
    pub(super) is_derived: bool,
}
