// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::time::Duration;

use crate::scan::Coverage;

use super::model::Rtt;

#[derive(Clone, Debug, Default)]
pub(crate) struct RttAccumulator {
    unavailable: u64,
    pending: u64,
    sent: u64,
    received: u64,
    total: Duration,
    min: Option<Duration>,
    max: Option<Duration>,
}

impl RttAccumulator {
    pub(crate) fn note_sent(&mut self) {
        self.sent = self.sent.saturating_add(1);
    }

    pub(crate) fn note_no_reply(&mut self, coverage: Coverage) {
        if coverage == Coverage::Pending {
            self.pending = self.pending.saturating_add(1);
        } else if !coverage.permits_silence() {
            self.unavailable = self.unavailable.saturating_add(1);
        }
    }

    pub(crate) fn qualify_pending(&mut self, coverage: Coverage) {
        if !coverage.permits_silence() {
            self.unavailable = self.unavailable.saturating_add(self.pending);
        }
        self.pending = 0;
    }

    pub(crate) fn note_received(&mut self, sample: Duration) {
        self.received = self.received.saturating_add(1);
        self.total = self.total.saturating_add(sample);
        self.min = Some(self.min.map_or(sample, |min| min.min(sample)));
        self.max = Some(self.max.map_or(sample, |max| max.max(sample)));
    }

    pub(crate) fn finish(&self) -> Rtt {
        // received is bounded by the operation probe budget, far below u32::MAX;
        // checked_div guards the narrowing anyway.
        let avg = u32::try_from(self.received)
            .ok()
            .and_then(|count| self.total.checked_div(count));
        Rtt {
            sent: self.sent,
            received: self.received,
            lost: self
                .sent
                .saturating_sub(self.received)
                .saturating_sub(self.unavailable)
                .saturating_sub(self.pending),
            unavailable: self.unavailable.saturating_add(self.pending),
            min: self.min,
            avg,
            max: self.max,
        }
    }
}
