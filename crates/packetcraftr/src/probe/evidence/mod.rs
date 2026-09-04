// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private response-evidence accounting and ordering shared by workflows.

pub(crate) use budget::{
    EvidenceDiagnosticDescriptor, EvidenceLimits, EvidenceState, Retained, UndecodedRetention,
    retain_evidence,
};
pub(crate) use candidate_selection::{
    ResponseCandidate, ResponseSelector, response_within_deadline, update_best_candidate,
};
pub(crate) use exact_validation::{
    ExchangeEvidenceError, format_exchange_evidence_error, validate_aggregate_evidence_limits,
    validate_batch_evidence, validate_capture_statistics_evidence,
    validate_response_frames_and_deadlines, validate_sent_byte_accounting,
};
pub(crate) use limits::{
    check_limits, check_probe_count, check_probe_duration, duration_violation,
};

mod budget;
mod candidate_selection;
mod exact_validation;
mod limits;

#[cfg(test)]
mod tests;
