// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact traceroute executor-evidence validation and accounting errors.

use crate::probe::evidence::{format_exchange_evidence_error, validate_batch_exchange_evidence};

use super::error::Error;
use super::model::{Batch, Execution, Limits};
use super::probe::sent_traceroute_probe_matches;

pub(super) fn validate_execution(
    batch: &Batch,
    execution: &Execution,
    limits: Limits,
) -> Result<(), Error> {
    validate_batch_exchange_evidence(
        batch,
        execution,
        limits.max_evidence_frames,
        limits.max_evidence_bytes,
        sent_traceroute_probe_matches,
    )
    .map_err(|error| Error::InvalidEvidence {
        sequence: error
            .request_index()
            .and_then(|index| batch.probes.get(index))
            .or_else(|| batch.probes.first())
            .map_or(0, |probe| probe.sequence),
        message: format_exchange_evidence_error(error, "hop batch", "traceroute"),
    })
}
