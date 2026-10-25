// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::budget::DeadlineExceeded;

use crate::evidence::Limits as EvidenceLimits;
use crate::exchange::Collection;

pub(crate) fn check_probe_count<E>(
    errors: fn(u64, crate::error::Failure) -> E,
    total_probes: usize,
    max_probes: usize,
) -> Result<(), E> {
    if total_probes > max_probes {
        return Err((errors)(
            0_u64,
            crate::error::Failure::InvalidLimit {
                field: "probes",
                value: u64::try_from(total_probes).unwrap_or(u64::MAX),
                reason: format!("exceeds max_probes={max_probes}"),
            },
        ));
    }
    Ok(())
}

pub(crate) fn check_collection_evidence<E>(
    errors: fn(u64, crate::error::Failure) -> E,
    collection: &Collection,
    limits: EvidenceLimits,
) -> Result<(), E> {
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
            return Err((errors)(
                0_u64,
                crate::error::Failure::InvalidLimit {
                    field,
                    value: u64::try_from(captured).unwrap_or(u64::MAX),
                    reason: format!("exceeds {name}={limit}"),
                },
            ));
        }
    }
    Ok(())
}

pub(crate) fn check_probe_duration<E>(
    errors: fn(u64, crate::error::Failure) -> E,
    worst_case: Duration,
    max_duration: Duration,
) -> Result<(), E> {
    if worst_case > max_duration {
        return Err((errors)(
            0_u64,
            crate::error::Failure::DurationLimit(DeadlineExceeded {
                actual: worst_case,
                limit: max_duration,
            }),
        ));
    }
    Ok(())
}
