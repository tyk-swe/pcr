// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The probe count and duration checks every scan and traceroute plan must
//! pass.

use std::time::Duration;

use packetcraftr_core::budget::DeadlineExceeded;

use crate::execution::Errors;

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
