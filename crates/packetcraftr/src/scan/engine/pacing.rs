// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, Instant};

use packetcraftr_core::budget::Deadline;

use crate::clock::Clock;
use crate::execution::{pause, rate_delay};

use super::pipelined::add_stats;
use crate::scan::Error;
use crate::scan::Request;
use crate::scan::error::Probes;

/// Transmissions whose rate pause is still owed, and when the last of them
/// began, if that is known.
#[derive(Debug, Default)]
pub(super) struct Owed {
    pub(super) transmissions: usize,
    pub(super) since: Option<Instant>,
}

impl Owed {
    /// Owes the pause of `transmissions` more, the last of which began at
    /// `began`. Several at once leave their last start unknown.
    pub(super) fn owe(&mut self, transmissions: usize, began: Option<Instant>) {
        if transmissions == 0 {
            return;
        }
        self.transmissions = self.transmissions.saturating_add(transmissions);
        self.since = began.filter(|_| transmissions == 1);
    }
}

/// Waits out the rate for the `owed` transmissions sent since the last
/// wait, just before the next one is sent. Time already spent since the last
/// of them began, such as its wait for a reply, counts toward the pause.
pub(super) fn settle<C: Clock>(
    request: &Request,
    clock: &mut C,
    deadline: &mut Deadline,
    owed: &mut Owed,
    stats: &mut crate::Stats,
) -> Result<(), Error> {
    let Owed {
        transmissions,
        since,
    } = std::mem::take(owed);
    if transmissions == 0 {
        return Ok(());
    }
    let spent = since.map_or(Duration::ZERO, |since| {
        clock.now().saturating_duration_since(since)
    });
    pace(request, clock, deadline, transmissions, spent, stats)
}

/// Waits out the request rate for `items` probes already sent, less the
/// `spent` time since the last began, recording
/// the pause in the aggregate statistics like the probe runners do. The
/// delay is reserved against the deadline before the sleep and the deadline
/// is enforced again after, so the operation's boundary stays authoritative.
pub(super) fn pace<C: Clock>(
    request: &Request,
    clock: &mut C,
    deadline: &mut Deadline,
    items: usize,
    spent: Duration,
    stats: &mut crate::Stats,
) -> Result<(), Error> {
    let delay = rate_delay(
        &Probes,
        "probes_per_second",
        items,
        request.probes_per_second,
    )?
    .saturating_sub(spent);
    if delay.is_zero() {
        return Ok(());
    }
    pause(deadline, clock, delay).map_err(|paused| paused.into_error(&Probes, 0))?;
    add_stats(
        stats,
        &crate::Stats {
            elapsed: delay,
            ..crate::Stats::default()
        },
        0,
    )
}
