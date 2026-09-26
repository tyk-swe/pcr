// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The probe count and duration checks every scan and traceroute plan must
//! pass.

use std::time::Duration;

use crate::probe::{Error, ErrorKind, Workflow};

pub(crate) fn check_probe_count(
    workflow: Workflow,
    total_probes: usize,
    max_probes: usize,
) -> Result<(), Error> {
    if total_probes > max_probes {
        return Err(Error::new(
            workflow,
            ErrorKind::InvalidLimit {
                field: "probes",
                value: u64::try_from(total_probes).unwrap_or(u64::MAX),
                reason: format!("exceeds max_probes={max_probes}"),
            },
        ));
    }
    Ok(())
}

pub(crate) fn check_probe_duration(
    workflow: Workflow,
    worst_case: Duration,
    max_duration: Duration,
) -> Result<(), Error> {
    if worst_case > max_duration {
        return Err(Error::new(
            workflow,
            ErrorKind::DurationLimit {
                actual: worst_case,
                limit: max_duration,
            },
        ));
    }
    Ok(())
}
