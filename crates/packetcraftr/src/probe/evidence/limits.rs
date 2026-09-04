// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared request-limit checks for bounded workflow evidence budgets.

use std::time::Duration;

use crate::probe::{Error, ErrorKind, Workflow};

/// Rejects, in order, the first `(field, value, maximum)` limit that is zero or
/// above its maximum and then the first `(field, value, maximum, reason)` limit
/// that exceeds another limit. Each workflow keeps its own error type, so the
/// offending triple is handed to `invalid`, which keeps every message and
/// classification code local to the workflow that owns it.
pub(crate) fn check_limits<E>(
    ranges: &[(&'static str, usize, usize)],
    bounded_by: &[(&'static str, usize, usize, &str)],
    invalid: impl Fn(&'static str, u64, String) -> E,
) -> Result<(), E> {
    for &(field, value, maximum) in ranges {
        if value == 0 || value > maximum {
            return Err(invalid(
                field,
                widen(value),
                format!("must be within 1..={maximum}"),
            ));
        }
    }
    for &(field, value, maximum, reason) in bounded_by {
        if value > maximum {
            return Err(invalid(field, widen(value), reason.to_owned()));
        }
    }
    Ok(())
}

/// Reports a duration limit that is zero or above `maximum`.
pub(crate) const fn duration_violation(value: Duration, maximum: Duration) -> bool {
    value.is_zero() || value.as_nanos() > maximum.as_nanos()
}

/// Rejects a probe plan that exceeds its finite probe budget.
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

/// Rejects a probe plan whose worst-case duration exceeds its finite limit.
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

fn widen(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
