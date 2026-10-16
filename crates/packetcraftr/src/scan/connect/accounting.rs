// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Evidence charges and scan statistics shared by discovery and scanning.

use std::time::Instant;

use super::super::discovery::{Observation, ReasonKind};
use super::super::report::RttAccumulator;
use super::super::{Error, Request, Stage};
use super::{Outcome, ProbeEvidence, Stats, invalid};

/// Totals shared by both stages.
pub(super) struct Progress {
    pub(super) stats: Stats,
    pub(super) rtt: RttAccumulator,
    pub(super) evidence_bytes: usize,
    pub(super) next_start: Instant,
    pub(super) peak: usize,
    pub(super) retries: usize,
    pub(super) discovery: Vec<Observation>,
}

/// Charges one settled probe to the evidence budget and the statistics, and
/// keeps a discovery outcome for the host records.
pub(super) fn record(
    request: &Request,
    progress: &mut Progress,
    probe: &ProbeEvidence,
) -> Result<(), Error> {
    progress.evidence_bytes = progress
        .evidence_bytes
        .checked_add(std::mem::size_of::<ProbeEvidence>())
        .and_then(|bytes| {
            bytes.checked_add(
                probe
                    .scope
                    .as_ref()
                    .map_or(0, crate::target::ResolvedZone::retained_bytes),
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(
                probe
                    .error
                    .as_ref()
                    .map_or(0, |error| error.to_string().len()),
            )
        })
        .filter(|bytes| *bytes <= request.limits.evidence.max_bytes)
        .ok_or_else(|| {
            invalid(
                "max_evidence_bytes",
                request.limits.evidence.max_bytes,
                "socket evidence budget exceeded",
            )
        })?;
    let stats = &mut progress.stats;
    stats.connections_attempted += u64::from(probe.attempted);
    progress.retries += usize::from(probe.attempted && probe.attempt > 1);
    stats.connections_succeeded += u64::from(probe.connect_succeeded == Some(true));
    if probe.attempted {
        progress.rtt.note_sent();
    }
    if matches!(
        probe.outcome.measurement(),
        super::super::measurement::Measurement::Response(_)
    ) {
        progress.rtt.note_received(probe.elapsed);
    }
    if probe.attempted
        && matches!(
            probe.outcome.measurement(),
            super::super::Measurement::Unavailable
        )
    {
        progress.rtt.note_no_reply(super::super::Coverage::Unknown);
    }
    if probe.stage == Stage::Discovery {
        // The operating system reports the endpoint's own answer; which
        // device sent it is not observable through a socket.
        let kind = match probe.outcome {
            Outcome::Connected => Some(ReasonKind::Connected),
            Outcome::Refused => Some(ReasonKind::Refused),
            Outcome::TimedOut
            | Outcome::Unreachable
            | Outcome::LocalError
            | Outcome::DeadlineExpired => None,
        };
        progress.discovery.push(Observation {
            sequence: probe.sequence,
            address: probe.endpoint.ip(),
            interface: probe.scope.as_ref().map(|scope| scope.interface.clone()),
            response: kind.map(|kind| (kind, probe.endpoint.ip())),
            observed_at: probe.finished_at.unwrap_or(probe.scheduled_at),
        });
    }
    Ok(())
}
