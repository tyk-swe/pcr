// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::time::Instant;

/// Each pending probe occupies one scheduled or draining entry. Removed probes
/// leave no stale deadlines; expiry discovery touches only the due prefix.
#[derive(Default)]
pub(super) struct PendingDeadlines {
    scheduled: BTreeSet<(Instant, usize)>,
    draining: BTreeSet<usize>,
    #[cfg(test)]
    visits: usize,
}

impl PendingDeadlines {
    pub(super) fn insert(&mut self, deadline: Instant, index: usize) {
        self.scheduled.insert((deadline, index));
    }

    pub(super) fn remove(&mut self, deadline: Instant, index: usize) {
        self.scheduled.remove(&(deadline, index));
        self.draining.remove(&index);
    }

    /// Moves newly due entries to the draining cohort. Cohort completion uses
    /// original probe order, independent of the order in which deadlines pass.
    pub(super) fn notice_expired(&mut self, now: Instant) -> bool {
        let mut changed = false;
        #[cfg(test)]
        {
            self.visits += 1;
        }
        while let Some((deadline, index)) = self.scheduled.first().copied() {
            if deadline > now {
                break;
            }
            self.scheduled.pop_first();
            changed |= self.draining.insert(index);
            #[cfg(test)]
            {
                self.visits += 1;
            }
        }
        changed
    }

    pub(super) fn is_draining(&self) -> bool {
        !self.draining.is_empty()
    }

    pub(super) fn pop_expired(&mut self) -> Option<usize> {
        self.draining.pop_first()
    }

    pub(super) fn next(&self) -> Option<Instant> {
        self.scheduled.first().map(|(deadline, _)| *deadline)
    }
}

/// Conservative node/capacity charge for both indexes, including insertion
/// overlap while an entry moves into the draining cohort.
pub(super) fn charge(pending: usize) -> usize {
    pending.saturating_add(1).saturating_mul(256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn unrelated_polls_do_not_visit_pending_entries() {
        for count in [32, 128, 512, 4096] {
            let now = Instant::now();
            let end = now + Duration::from_secs(1);
            let mut deadlines = PendingDeadlines::default();
            for index in 0..count {
                deadlines.insert(end, index);
            }
            for _ in 0..1000 {
                assert!(!deadlines.notice_expired(now));
                assert_eq!(deadlines.next(), Some(end));
            }
            assert_eq!(deadlines.visits, 1000);
            assert!(deadlines.notice_expired(end));
            assert_eq!(deadlines.visits, 1000 + count + 1);
            for index in 0..count {
                assert_eq!(deadlines.pop_expired(), Some(index));
            }
            assert_eq!(deadlines.pop_expired(), None);
            assert_eq!(deadlines.next(), None);
        }
    }

    #[test]
    fn removal_and_reuse_leave_no_stale_deadlines_or_draining_entries() {
        let now = Instant::now();
        let mut deadlines = PendingDeadlines::default();
        deadlines.insert(now + Duration::from_secs(2), 0);
        deadlines.insert(now + Duration::from_secs(1), 1);
        deadlines.remove(now + Duration::from_secs(2), 0);
        deadlines.insert(now + Duration::from_secs(3), 0);
        assert_eq!(deadlines.next(), Some(now + Duration::from_secs(1)));
        deadlines.notice_expired(now + Duration::from_secs(2));
        deadlines.remove(now + Duration::from_secs(1), 1);
        assert!(!deadlines.is_draining());
        assert_eq!(deadlines.next(), Some(now + Duration::from_secs(3)));
        deadlines.notice_expired(now + Duration::from_secs(3));
        assert_eq!(deadlines.pop_expired(), Some(0));
        deadlines.remove(now + Duration::from_secs(3), 0);
        assert!(deadlines.scheduled.is_empty());
        assert!(deadlines.draining.is_empty());
    }
}
