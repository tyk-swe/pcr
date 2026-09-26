// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Range and cross-limit checks every live workflow request validates.

use std::time::Duration;

/// Rejects the first zero or excessive range limit, then the first cross-limit
/// violation. `invalid` constructs the owning workflow's error and
/// classification.
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

/// The evidence-retention bounds every live workflow validates against the
/// same ceilings. `max_undecoded` is [`Some`] when the workflow bounds
/// undecoded retention; it must not exceed the frame bound.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CaptureEvidenceLimits {
    pub(crate) max_evidence_frames: usize,
    pub(crate) max_evidence_bytes: usize,
    pub(crate) max_undecoded: Option<usize>,
}

impl CaptureEvidenceLimits {
    /// Rejects shared evidence bounds above their ceilings, then an undecoded
    /// bound above the frame bound.
    pub(crate) fn validate<E>(
        &self,
        invalid: impl Fn(&'static str, u64, String) -> E,
    ) -> Result<(), E> {
        check_limits(
            &[
                (
                    "max_evidence_frames",
                    self.max_evidence_frames,
                    packetcraftr_netio::capture::MAX_CAPTURE_QUEUE_FRAMES,
                ),
                (
                    "max_evidence_bytes",
                    self.max_evidence_bytes,
                    packetcraftr_netio::capture::MAX_CAPTURE_QUEUE_BYTES,
                ),
            ],
            &[],
            &invalid,
        )?;
        if let Some(max_undecoded) = self.max_undecoded {
            check_limits(
                &[],
                &[(
                    "max_undecoded",
                    max_undecoded,
                    self.max_evidence_frames,
                    "cannot exceed max_evidence_frames",
                )],
                invalid,
            )?;
        }
        Ok(())
    }
}

/// Reports a duration limit that is zero or above `maximum`.
pub(crate) const fn duration_violation(value: Duration, maximum: Duration) -> bool {
    value.is_zero() || value.as_nanos() > maximum.as_nanos()
}

fn widen(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
