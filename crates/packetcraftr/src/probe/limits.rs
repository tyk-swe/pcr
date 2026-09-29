// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::budget::DeadlineExceeded;

use crate::exchange::Collection;
use crate::execution::Errors;
use crate::execution::limits::EvidenceLimits;

pub(crate) fn check_probe_count<G: Errors>(
    errors: &G,
    total_probes: usize,
    max_probes: usize,
) -> Result<(), G::Error> {
    if total_probes > max_probes {
        return Err(errors.invalid_limit(
            "probes",
            u64::try_from(total_probes).unwrap_or(u64::MAX),
            format!("exceeds max_probes={max_probes}"),
        ));
    }
    Ok(())
}

pub(crate) fn check_collection_evidence<G: Errors>(
    errors: &G,
    collection: &Collection,
    limits: EvidenceLimits,
) -> Result<(), G::Error> {
    let capture = &collection.capture;
    for (field, captured, limit, name) in [
        (
            "capture_max_frames",
            capture.max_frames,
            limits.max_frames,
            "max_evidence_frames",
        ),
        (
            "capture_max_bytes",
            capture.max_bytes,
            limits.max_bytes,
            "max_evidence_bytes",
        ),
    ] {
        if captured > limit {
            return Err(errors.invalid_limit(
                field,
                u64::try_from(captured).unwrap_or(u64::MAX),
                format!("exceeds {name}={limit}"),
            ));
        }
    }
    Ok(())
}

pub(crate) fn check_probe_duration<G: Errors>(
    errors: &G,
    worst_case: Duration,
    max_duration: Duration,
) -> Result<(), G::Error> {
    if worst_case > max_duration {
        return Err(errors.duration_limit(
            G::Step::default(),
            DeadlineExceeded {
                actual: worst_case,
                limit: max_duration,
            },
        ));
    }
    Ok(())
}
