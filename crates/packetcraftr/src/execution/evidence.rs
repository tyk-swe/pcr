// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private response-evidence accounting and ordering shared by workflows.

pub(crate) use budget::{EvidenceDiagnosticDescriptor, EvidenceSink, EvidenceState};
pub(crate) use candidate_selection::{
    CandidateKey, Passed, ResponseCandidate, ResponseSelector, candidate_precedes,
};

mod budget;
mod candidate_selection;

#[cfg(test)]
mod tests;
