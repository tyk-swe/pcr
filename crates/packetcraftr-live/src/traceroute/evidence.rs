// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact traceroute executor-evidence validation and accounting errors.

use crate::probe::evidence::{
    ExchangeEvidence, ExchangeEvidenceError, format_exchange_evidence_error,
    validate_exchange_evidence as validate_shared_exchange_evidence,
};

use super::error::TracerouteError;
use super::model::{TracerouteBatch, TracerouteBatchExecution, TracerouteLimits};
use super::probe::sent_traceroute_probe_matches;

pub(super) fn validate_execution(
    batch: &TracerouteBatch,
    execution: &TracerouteBatchExecution,
    limits: TracerouteLimits,
) -> Result<(), TracerouteError> {
    validate_shared_exchange_evidence(
        ExchangeEvidence {
            request_count: batch.probes.len(),
            sent: &execution.sent,
            matched_responses: &execution.responses,
            unsolicited: &execution.unsolicited,
            undecoded: &execution.undecoded,
            timeout: batch.timeout,
            stats: &execution.stats,
        },
        limits.max_evidence_frames,
        limits.max_evidence_bytes,
        |request_index, sent| sent_traceroute_probe_matches(&batch.probes[request_index], sent),
    )
    .map_err(|error| map_traceroute_evidence_error(batch, error))
}

fn map_traceroute_evidence_error(
    batch: &TracerouteBatch,
    error: ExchangeEvidenceError,
) -> TracerouteError {
    let batch_sequence = batch.probes[0].sequence;
    let sequence = match &error {
        ExchangeEvidenceError::SentPacketMismatch { request_index } => {
            batch.probes[*request_index].sequence
        }
        _ => batch_sequence,
    };
    let message = format_exchange_evidence_error(error, "hop batch", "traceroute");
    TracerouteError::InvalidEvidence { sequence, message }
}
