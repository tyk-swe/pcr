// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private response-evidence accounting and ordering shared by workflows.

pub(crate) use budget::{
    EvidenceBudget, EvidenceDiagnosticDescriptor, push_undecoded_limit_diagnostic, retain_evidence,
    retain_undecoded_frames,
};
pub(crate) use candidate_selection::{
    ResponseCandidate, ResponseSelector, response_within_deadline, select_response_candidate,
};
pub(crate) use exact_validation::{
    ExchangeEvidence, ExchangeEvidenceError, MatchedResponseEvidence, ResponseEvidence,
    format_exchange_evidence_error, validate_exchange_evidence,
};

mod budget;
mod candidate_selection;
mod exact_validation;

#[cfg(test)]
mod tests;
