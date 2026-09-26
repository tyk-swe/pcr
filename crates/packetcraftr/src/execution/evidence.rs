// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private response-evidence accounting and ordering shared by workflows.
//!
//! Workflows retain evidence only through [`EvidenceState`], which owns the
//! operation-wide frame budget, undecoded retention and diagnostic log, and
//! pick responses only through [`ResponseSelector`]. The pipelined scan
//! orders its in-flight candidates with the selector's [`candidate_precedes`].

pub(crate) use budget::{
    EvidenceDiagnosticDescriptor, EvidenceLimits, EvidenceSink, EvidenceState,
};
pub(crate) use candidate_selection::{
    CandidateKey, ResponseCandidate, ResponseSelector, candidate_precedes,
};

mod budget;
mod candidate_selection;

#[cfg(test)]
mod tests;
