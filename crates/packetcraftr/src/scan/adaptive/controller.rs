// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use packetcraftr_netio::interface;

use crate::target::{ResolvedZone, SelectedAddress};

mod settlement;

use super::estimator::Estimator;
use super::work::{Endpoint, Operations, Selection, Slot, Wave, Work};
use super::{Adaptive, Ceilings, Condition, HostIdentity, Scheduling, SchedulingMode};

pub(super) const CITED_SEQUENCES: usize = 8;

#[derive(Default)]
pub(super) struct ControlResponder {
    count: u64,
    sequences: Vec<u64>,
}

pub(super) struct Host {
    key: (IpAddr, Option<interface::Id>),
    scope: Option<ResolvedZone>,
    estimator: Estimator,
    pub(super) first_admission: Option<Instant>,
    last_send: Option<Instant>,
    pub(super) uncommitted: usize,
    pub(super) min_gap: Duration,
    completed: u64,
    replies: u64,
    pub(super) losses: u64,
    control: HashMap<IpAddr, ControlResponder>,
    control_errors: u64,
    loss_sequences: Vec<u64>,
    pub(super) pending_losses: u64,
    pub(super) pending_loss_sequences: Vec<u64>,
    condition_raised: bool,
    incomplete: bool,
}

#[derive(Clone, Copy, Debug)]
pub(in crate::scan) enum Outcome {
    Reply {
        latency: Duration,
        responder: IpAddr,
        control: bool,
    },
    Silent,
    /// Capture is still active: retry without attributing loss or reducing the window.
    UnqualifiedSilence,
    Aborted,
    Omitted,
}

pub(in crate::scan) struct Controller {
    pub(super) config: Adaptive,
    initial_timeout: Duration,
    max_in_flight: usize,
    operation: Estimator,
    pub(super) hosts: Vec<Host>,
    indices: HashMap<(IpAddr, Option<interface::Id>), usize>,
    window: usize,
    peak_window: usize,
    successes: usize,
    retries_started: u64,
    cohort: u64,
    pub(super) halved: std::collections::HashSet<u64>,
    pub(super) cohort_members: HashMap<u64, usize>,
    conditions: Vec<Condition>,
    incomplete: Vec<HostIdentity>,
    defer_conditions: bool,
}

impl Controller {
    pub(in crate::scan) fn new(
        config: Adaptive,
        initial_timeout: Duration,
        max_in_flight: usize,
    ) -> Self {
        Self {
            config,
            initial_timeout,
            max_in_flight,
            operation: Estimator::default(),
            hosts: Vec::new(),
            indices: HashMap::new(),
            window: config.initial_window,
            peak_window: 0,
            successes: 0,
            retries_started: 0,
            cohort: 0,
            halved: std::collections::HashSet::new(),
            cohort_members: HashMap::new(),
            conditions: Vec::new(),
            incomplete: Vec::new(),
            defer_conditions: false,
        }
    }

    pub(in crate::scan) fn window(&self) -> usize {
        self.window.min(self.max_in_flight)
    }

    pub(in crate::scan) fn host_index(&mut self, target: &SelectedAddress) -> usize {
        let key = target.key();
        if let Some(index) = self.indices.get(&key) {
            return *index;
        }
        let index = self.hosts.len();
        self.hosts.push(Host {
            key: key.clone(),
            scope: target.scope.clone(),
            estimator: Estimator::default(),
            first_admission: None,
            last_send: None,
            uncommitted: 0,
            min_gap: Duration::ZERO,
            completed: 0,
            replies: 0,
            losses: 0,
            control: HashMap::new(),
            control_errors: 0,
            loss_sequences: Vec::new(),
            pending_losses: 0,
            pending_loss_sequences: Vec::new(),
            condition_raised: false,
            incomplete: false,
        });
        self.indices.insert(key, index);
        index
    }

    pub(in crate::scan) fn host_expired(&self, host: usize, now: Instant) -> bool {
        self.hosts[host]
            .first_admission
            .is_some_and(|started| now >= started + self.config.host_timeout)
    }

    pub(in crate::scan) fn host_remaining(&self, host: usize, now: Instant) -> Duration {
        match self.hosts[host].first_admission {
            Some(started) => (started + self.config.host_timeout).saturating_duration_since(now),
            None => self.config.host_timeout,
        }
    }

    pub(in crate::scan) fn host_started(&mut self, host: usize, now: Instant) {
        self.hosts[host].first_admission.get_or_insert(now);
    }

    fn find(&self, target: &SelectedAddress) -> Option<usize> {
        self.indices.get(&target.key()).copied()
    }

    pub(super) fn is_incomplete(&self, host: usize) -> bool {
        self.hosts[host].incomplete
    }

    pub(in crate::scan) fn incomplete_targets<'a>(
        &'a self,
        targets: &'a [SelectedAddress],
    ) -> impl Iterator<Item = usize> + 'a {
        targets
            .iter()
            .enumerate()
            .filter_map(move |(index, target)| {
                self.find(target)
                    .is_some_and(|host| self.is_incomplete(host))
                    .then_some(index)
            })
    }

    pub(in crate::scan) fn mark_incomplete(&mut self, host: usize) {
        let host = &mut self.hosts[host];
        if host.incomplete {
            return;
        }
        host.incomplete = true;
        self.incomplete.push(HostIdentity {
            address: host.key.0,
            scope: host.scope.clone(),
        });
    }

    fn rto(&self, host: usize) -> Duration {
        if let Some(rto) = self.hosts[host]
            .estimator
            .rto(self.config.min_timeout, self.config.max_timeout)
        {
            return rto;
        }
        self.operation
            .rto(self.config.min_timeout, self.config.max_timeout)
            .unwrap_or(self.initial_timeout)
            .max(self.initial_timeout)
            .clamp(self.config.min_timeout, self.config.max_timeout)
    }

    pub(in crate::scan) fn open_stage(
        &mut self,
        targets: &[SelectedAddress],
        endpoint_count: usize,
        max_attempts: u32,
        first_sequence: u64,
        now: Instant,
    ) -> Work {
        let slots = targets
            .iter()
            .map(|target| Slot {
                host: self.host_index(target),
                endpoints: vec![
                    Endpoint {
                        sent: 0,
                        pending: false,
                        finished: false,
                        ready_at: now,
                    };
                    endpoint_count
                ],
                ready: (0..endpoint_count).collect(),
                delayed: BTreeSet::new(),
                unfinished: endpoint_count,
                wake: None,
                expiration: None,
            })
            .collect::<Vec<_>>();
        let unfinished = slots.len().saturating_mul(endpoint_count);
        let host_count = self.hosts.len();
        let mut work = Work {
            slots,
            cursor: 0,
            runnable: BTreeSet::new(),
            wakes: BTreeSet::new(),
            expirations: BTreeSet::new(),
            unfinished,
            max_attempts,
            first_sequence,
            host_count,
            canceled_responses: 0,
            operations: Operations::starting(unfinished),
        };
        for slot in 0..work.slots.len() {
            self.refresh_slot(&mut work, slot, now);
        }
        work
    }

    pub(in crate::scan) fn take_canceled_responses(&self, work: &mut Work) -> usize {
        std::mem::take(&mut work.canceled_responses)
    }

    /// Replaces a slot's single wake/expiry index entries. No stale heap
    /// entries accumulate across retries, pacing changes, or stage completion.
    fn refresh_slot(&self, work: &mut Work, index: usize, now: Instant) {
        let slot = &mut work.slots[index];
        work.runnable.remove(&index);
        work.operations.ready();
        if let Some(wake) = slot.wake.take() {
            work.wakes.remove(&(wake, index));
            work.operations.time();
        }
        if let Some(expiration) = slot.expiration.take() {
            work.expirations.remove(&(expiration, index));
            work.operations.time();
        }
        if slot.unfinished == 0 {
            return;
        }
        let host = &self.hosts[slot.host];
        if let Some(started) = host.first_admission {
            let expiration = started + self.config.host_timeout;
            work.expirations.insert((expiration, index));
            work.operations.time();
            slot.expiration = Some(expiration);
        }
        if host.min_gap > Duration::ZERO && host.uncommitted > 0 {
            return;
        }
        let gap = host.last_send.map(|last| last + host.min_gap);
        let ready_time = (!slot.ready.is_empty()).then(|| gap.unwrap_or(now));
        if ready_time.is_some_and(|ready| ready <= now) {
            work.runnable.insert(index);
            work.operations.ready();
        }
        // Delayed retries must wake even while later first attempts are ready:
        // on promotion the endpoint's original index restores deterministic order.
        let retry_time = slot
            .delayed
            .first()
            .map(|(ready, _)| gap.map_or(*ready, |gap| gap.max(*ready)));
        let wake = ready_time
            .filter(|ready| *ready > now)
            .into_iter()
            .chain(retry_time)
            .min();
        if let Some(wake) = wake {
            work.wakes.insert((wake, index));
            work.operations.time();
            slot.wake = Some(wake);
        }
    }

    fn expire(&mut self, work: &mut Work, now: Instant) {
        while let Some((expiration, index)) = work.expirations.first().copied() {
            if expiration > now {
                break;
            }
            work.expirations.pop_first();
            work.operations.time();
            let slot = &mut work.slots[index];
            slot.expiration = None;
            let remaining = slot.unfinished;
            let mut canceled = 0usize;
            for endpoint in &mut slot.endpoints {
                if !endpoint.finished {
                    canceled = canceled
                        .saturating_add(work.max_attempts.saturating_sub(endpoint.sent) as usize);
                    endpoint.finished = true;
                }
            }
            slot.unfinished = 0;
            slot.ready.clear();
            slot.delayed.clear();
            work.operations.ready();
            work.operations.time();
            work.unfinished = work.unfinished.saturating_sub(remaining);
            work.canceled_responses = work.canceled_responses.saturating_add(canceled);
            if remaining > 0 {
                self.mark_incomplete(slot.host);
            }
            self.refresh_slot(work, index, now);
        }
        while let Some((wake, index)) = work.wakes.first().copied() {
            if wake > now {
                break;
            }
            work.wakes.pop_first();
            work.operations.time();
            let slot = &mut work.slots[index];
            slot.wake = None;
            while slot.delayed.first().is_some_and(|(ready, _)| *ready <= now) {
                let (_, endpoint) = slot.delayed.pop_first().expect("due retry exists");
                slot.ready.insert(endpoint);
                work.operations.ready();
                work.operations.time();
            }
            self.refresh_slot(work, index, now);
        }
    }

    pub(in crate::scan) fn select(
        &mut self,
        work: &mut Work,
        now: Instant,
        operation_end: Instant,
        capacity: usize,
    ) -> Wave {
        self.expire(work, now);
        let cohort = self.cohort;
        self.cohort = self.cohort.saturating_add(1);
        let mut selections = Vec::new();
        let endpoints_per_host = work.slots.first().map_or(0, |slot| slot.endpoints.len());
        // Selection is provisional: connect callers can stop admitting a wave
        // on pacing or capacity refusal. Restore every selection before returning;
        // admitted() alone commits removal from the ready index.
        let mut held = Vec::new();
        let mut suppressed = Vec::new();
        while selections.len() < capacity {
            let Some(slot_index) = work
                .runnable
                .range(work.cursor..)
                .next()
                .copied()
                .or_else(|| work.runnable.first().copied())
            else {
                break;
            };
            work.cursor = (slot_index + 1) % work.slots.len();
            let slot = &mut work.slots[slot_index];
            let host = slot.host;
            let Some(endpoint_index) = slot.ready.pop_first() else {
                work.runnable.remove(&slot_index);
                work.operations.ready();
                continue;
            };
            work.operations.discovery();
            work.operations.ready();
            held.push((slot_index, endpoint_index));
            if slot.ready.is_empty() || self.hosts[host].min_gap > Duration::ZERO {
                work.runnable.remove(&slot_index);
                work.operations.ready();
                suppressed.push(slot_index);
            }
            let host_deadline = self.hosts[host]
                .first_admission
                .map_or(now + self.config.host_timeout, |started| {
                    started + self.config.host_timeout
                })
                .min(operation_end);
            let host_remaining = host_deadline.saturating_duration_since(now);
            if host_remaining.is_zero() {
                self.mark_incomplete(host);
                work.runnable.remove(&slot_index);
                work.operations.ready();
                suppressed.push(slot_index);
                continue;
            }
            let desired = self.rto(host);
            let timeout = desired.min(host_remaining);
            let attempt = work.slots[slot_index].endpoints[endpoint_index].sent + 1;
            let sequence = crate::scan::plan::sequence(
                work.first_sequence,
                attempt,
                endpoint_index,
                endpoints_per_host,
                host,
                work.host_count,
            );
            selections.push(Selection {
                slot: slot_index,
                endpoint: endpoint_index,
                host,
                attempt,
                sequence,
                timeout,
                host_deadline,
                cohort,
                host_limited: timeout < desired,
                selected_at: now,
            });
        }
        for (slot, endpoint) in held {
            work.slots[slot].ready.insert(endpoint);
            work.operations.ready();
        }
        for slot in suppressed {
            work.runnable.insert(slot);
            work.operations.ready();
        }
        let next_ready = work
            .wakes
            .first()
            .map(|(ready, _)| *ready)
            .into_iter()
            .chain(work.expirations.first().map(|(ready, _)| *ready))
            .min();
        Wave {
            selections,
            next_ready,
            done: work.unfinished == 0,
        }
    }

    pub(in crate::scan) fn admitted(&mut self, work: &mut Work, selection: Selection) {
        let slot = &mut work.slots[selection.slot];
        slot.endpoints[selection.endpoint].pending = true;
        slot.ready.remove(&selection.endpoint);
        work.operations.ready();
        *self.cohort_members.entry(selection.cohort).or_default() += 1;
        self.host_started(selection.host, selection.selected_at);
        self.hosts[selection.host].uncommitted += 1;
        self.refresh_slot(work, selection.slot, selection.selected_at);
    }

    /// Commits an admitted slot's attempt number and paces the host from the
    /// admission time; whether a probe actually started is counted separately.
    pub(in crate::scan) fn commit_attempt(
        &mut self,
        work: &mut Work,
        selection: Selection,
        admitted_at: Instant,
    ) {
        let slot = &mut work.slots[selection.slot];
        let endpoint = &mut slot.endpoints[selection.endpoint];
        debug_assert!(
            endpoint.sent + 1 == selection.attempt,
            "a committed attempt continues the endpoint's count"
        );
        endpoint.sent = selection.attempt;
        self.hosts[selection.host].uncommitted =
            self.hosts[selection.host].uncommitted.saturating_sub(1);
        self.host_started(selection.host, admitted_at);
        self.hosts[selection.host].last_send = Some(admitted_at);
        self.refresh_slot(work, selection.slot, admitted_at);
    }

    /// Counts an attempt a provider actually started as a retry past the first.
    pub(in crate::scan) fn note_attempted(&mut self, selection: Selection) {
        if selection.attempt > 1 {
            self.retries_started = self.retries_started.saturating_add(1);
        }
    }

    pub(in crate::scan) fn confirm_send(
        &mut self,
        work: &mut Work,
        selection: Selection,
        sent_at: Instant,
    ) {
        self.commit_attempt(work, selection, sent_at);
        self.note_attempted(selection);
    }

    pub(in crate::scan) fn observe_active(&mut self, active: usize) {
        self.peak_window = self.peak_window.max(active);
    }

    pub(in crate::scan) fn host_gap_ready(&self, host: usize, now: Instant) -> bool {
        match self.hosts[host].last_send {
            Some(last) => last + self.hosts[host].min_gap <= now,
            None => true,
        }
    }

    pub(in crate::scan) fn finish(self, ceilings: Ceilings) -> Scheduling {
        Scheduling {
            mode: SchedulingMode::Adaptive,
            adaptive: Some(self.config),
            observed_peak_window: self.peak_window,
            retries_started: self.retries_started,
            conditions: self.conditions,
            incomplete: self.incomplete,
            operation_ceiling: ceilings.operation,
            process_ceiling: ceilings.process,
        }
    }
}
