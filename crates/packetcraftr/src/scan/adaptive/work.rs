// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

#[derive(Default)]
pub(super) struct Operations {
    #[cfg(test)]
    pub(super) discovery: usize,
    #[cfg(test)]
    pub(super) ready: usize,
    #[cfg(test)]
    pub(super) time: usize,
}

impl Operations {
    pub(super) fn starting(ready: usize) -> Self {
        let _ = ready;
        #[cfg(test)]
        {
            Self {
                ready,
                ..Self::default()
            }
        }
        #[cfg(not(test))]
        {
            Self::default()
        }
    }

    #[inline]
    pub(super) fn ready(&mut self) {
        #[cfg(test)]
        {
            self.ready += 1;
        }
    }

    #[inline]
    pub(super) fn time(&mut self) {
        #[cfg(test)]
        {
            self.time += 1;
        }
    }

    #[inline]
    pub(super) fn discovery(&mut self) {
        #[cfg(test)]
        {
            self.discovery += 1;
        }
    }
}

pub(in crate::scan) struct Work {
    pub(super) slots: Vec<Slot>,
    pub(super) cursor: usize,
    /// Only slots with immediately eligible work participate in round robin.
    pub(super) runnable: BTreeSet<usize>,
    pub(super) wakes: BTreeSet<(Instant, usize)>,
    pub(super) expirations: BTreeSet<(Instant, usize)>,
    pub(super) unfinished: usize,
    pub(super) max_attempts: u32,
    pub(super) first_sequence: u64,
    pub(super) host_count: usize,
    pub(super) canceled_responses: usize,
    pub(super) operations: Operations,
}

pub(super) struct Slot {
    pub(super) host: usize,
    pub(super) endpoints: Vec<Endpoint>,
    pub(super) ready: BTreeSet<usize>,
    pub(super) delayed: BTreeSet<(Instant, usize)>,
    pub(super) unfinished: usize,
    pub(super) wake: Option<Instant>,
    pub(super) expiration: Option<Instant>,
}

#[derive(Clone, Debug)]
pub(super) struct Endpoint {
    pub(super) sent: u32,
    pub(super) pending: bool,
    pub(super) finished: bool,
    pub(super) ready_at: Instant,
}

#[derive(Clone, Copy, Debug)]
pub(in crate::scan) struct Selection {
    pub slot: usize,
    pub endpoint: usize,
    pub host: usize,
    pub attempt: u32,
    pub sequence: u64,
    pub timeout: Duration,
    pub host_deadline: Instant,
    pub cohort: u64,
    pub host_limited: bool,
    pub selected_at: Instant,
}

pub(in crate::scan) struct Wave {
    pub selections: Vec<Selection>,
    pub next_ready: Option<Instant>,
    pub done: bool,
}

impl Work {
    pub(in crate::scan) fn done(&self) -> bool {
        self.unfinished == 0
    }
}
