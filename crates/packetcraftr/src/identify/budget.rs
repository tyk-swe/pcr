// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr_core::budget::Deadline;

use super::{Limit, Usage};

pub(super) struct Scope {
    pub limit: Limit,
    pub usage: Usage,
    pub deadline: Arc<Deadline>,
}

impl Scope {
    pub(super) fn new(limit: Limit, deadline: Deadline) -> Self {
        Self {
            limit,
            usage: Usage::default(),
            deadline: Arc::new(deadline),
        }
    }

    pub(super) fn available(&self, write_bytes: u64) -> bool {
        self.usage.attempts < self.limit.attempts
            && write_bytes
                <= self
                    .limit
                    .write_bytes
                    .saturating_sub(self.usage.write_bytes)
            && self.remaining_read() > 0
            && self.deadline.check_cancelled().is_ok()
            && !self.expired()
    }

    pub(super) fn expired(&self) -> bool {
        !self
            .deadline
            .remaining()
            .is_ok_and(|remaining| !remaining.is_zero())
    }

    pub(super) fn remaining_read(&self) -> u64 {
        self.limit.read_bytes.saturating_sub(self.usage.read_bytes)
    }

    pub(super) fn attempt(&mut self) {
        self.usage.attempts += 1;
    }

    pub(super) fn bytes(&mut self, written: u64, read: u64) {
        // Every call is bounded by the remaining allowances before I/O.
        self.usage.write_bytes += written;
        self.usage.read_bytes += read;
    }
}
