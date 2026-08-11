// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact scan executor-evidence validation and accounting errors.

use crate::probe::evidence::{format_exchange_evidence_error, validate_batch_exchange_evidence};

use super::error::ScanError;
use super::model::{ScanBatch, ScanBatchExecution, ScanLimits};
use super::probe::sent_scan_probe_matches;

pub(super) fn validate_exchange_evidence(
    batch: &ScanBatch,
    exchange: &ScanBatchExecution,
    limits: ScanLimits,
) -> Result<(), ScanError> {
    validate_batch_exchange_evidence(
        batch,
        exchange,
        limits.max_evidence_frames,
        limits.max_evidence_bytes,
        sent_scan_probe_matches,
    )
    .map_err(|error| ScanError::InvalidEvidence {
        sequence: error
            .request_index()
            .map_or(batch.probes[0].sequence, |index| {
                batch.probes[index].sequence
            }),
        message: format_exchange_evidence_error(error, "batch", "scan"),
    })
}
