// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use packetcraftr_netio::deadline::MAX_WAIT;
use packetcraftr_netio::interface;

use crate::execution::limits::duration_violation;
use crate::target::{ResolvedZone, SelectedAddress};

use super::Error;

const RTO_GRANULARITY: Duration = Duration::from_millis(1);
const CITED_SEQUENCES: usize = 8;
const INFERENCE_MIN_COMPLETED: u64 = 8;
const INFERENCE_MIN_CONTROL: usize = 2;
const INFERENCE_MIN_LOSSES: u64 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Adaptive {
    pub min_timeout: Duration,
    pub max_timeout: Duration,
    pub min_window: usize,
    pub initial_window: usize,
    pub host_timeout: Duration,
    pub retry_backoff: Duration,
    pub max_backoff: Duration,
}

impl Adaptive {
    pub(crate) fn validate(&self, request: &super::Request) -> Result<(), Error> {
        for value in [
            self.min_timeout,
            self.max_timeout,
            self.host_timeout,
            self.retry_backoff,
            self.max_backoff,
        ] {
            if duration_violation(value, MAX_WAIT) {
                return Err(Error::InvalidDuration {
                    value,
                    maximum: MAX_WAIT,
                });
            }
        }
        if !(self.min_timeout <= request.timeout && request.timeout <= self.max_timeout) {
            return Err(Error::InvalidTimeout {
                value: request.timeout,
                maximum: self.max_timeout.max(self.min_timeout),
            });
        }
        let invalid = |field: &'static str, value: usize, reason: String| {
            Err(Error::InvalidLimit {
                field,
                value: value as u64,
                reason,
            })
        };
        if self.min_window == 0 || self.initial_window < self.min_window {
            return invalid(
                "min_window",
                self.min_window,
                format!(
                    "must satisfy 1 <= min_window <= initial_window={}",
                    self.initial_window
                ),
            );
        }
        if self.initial_window > request.max_in_flight {
            return invalid(
                "initial_window",
                self.initial_window,
                format!("must not exceed max_in_flight={}", request.max_in_flight),
            );
        }
        if self.host_timeout > request.limits.max_duration {
            return Err(Error::InvalidDuration {
                value: self.host_timeout,
                maximum: request.limits.max_duration,
            });
        }
        if self.retry_backoff > self.max_backoff {
            return Err(Error::InvalidDuration {
                value: self.retry_backoff,
                maximum: self.max_backoff,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SchedulingMode {
    #[default]
    Fixed,
    Adaptive,
}

impl SchedulingMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::Adaptive => "adaptive",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostIdentity {
    pub address: IpAddr,
    pub scope: Option<ResolvedZone>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionKind {
    SuspectedResponseRateLimit,
}

impl ConditionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SuspectedResponseRateLimit => "suspected_response_rate_limit",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Condition {
    pub kind: ConditionKind,
    pub host: HostIdentity,
    pub control_responder: IpAddr,
    pub completed: u64,
    pub replies: u64,
    pub losses: u64,
    pub control_sequences: Vec<u64>,
    pub loss_sequences: Vec<u64>,
    pub caveat: &'static str,
}

#[derive(Clone, Debug, Default)]
pub struct Scheduling {
    pub mode: SchedulingMode,
    pub adaptive: Option<Adaptive>,
    pub observed_peak_window: usize,
    pub retries_started: u64,
    pub conditions: Vec<Condition>,
    pub incomplete: Vec<HostIdentity>,
    pub operation_ceiling: Option<usize>,
    pub process_ceiling: Option<usize>,
}

#[derive(Clone, Copy, Debug, Default)]
struct Estimator {
    srtt_ns: Option<u64>,
    rttvar_ns: u64,
}

impl Estimator {
    fn sample(&mut self, rtt: Duration) {
        let sample = u64::try_from(rtt.as_nanos()).unwrap_or(u64::MAX);
        match self.srtt_ns {
            None => {
                self.srtt_ns = Some(sample);
                self.rttvar_ns = sample / 2;
            }
            Some(srtt) => {
                let deviation = srtt.abs_diff(sample);
                self.rttvar_ns = self.rttvar_ns.saturating_mul(3).saturating_add(deviation) / 4;
                self.srtt_ns = Some(srtt.saturating_mul(7).saturating_add(sample) / 8);
            }
        }
    }

    fn rto(&self, min: Duration, max: Duration) -> Option<Duration> {
        let srtt = self.srtt_ns?;
        let jitter = self
            .rttvar_ns
            .saturating_mul(4)
            .max(u64::try_from(RTO_GRANULARITY.as_nanos()).unwrap_or(u64::MAX));
        Some(Duration::from_nanos(srtt.saturating_add(jitter)).clamp(min, max))
    }
}

#[derive(Default)]
struct ControlResponder {
    count: u64,
    sequences: Vec<u64>,
}

struct Host {
    key: (IpAddr, Option<interface::Id>),
    scope: Option<ResolvedZone>,
    estimator: Estimator,
    first_admission: Option<Instant>,
    last_send: Option<Instant>,
    uncommitted: usize,
    min_gap: Duration,
    completed: u64,
    replies: u64,
    losses: u64,
    control: HashMap<IpAddr, ControlResponder>,
    control_errors: u64,
    loss_sequences: Vec<u64>,
    pending_losses: u64,
    pending_loss_sequences: Vec<u64>,
    condition_raised: bool,
    incomplete: bool,
}

#[derive(Clone, Debug)]
struct Endpoint {
    sent: u32,
    pending: bool,
    finished: bool,
    ready_at: Instant,
}

pub(super) struct Work {
    slots: Vec<Slot>,
    cursor: usize,
    /// Only slots with immediately eligible work participate in round robin.
    runnable: BTreeSet<usize>,
    wakes: BTreeSet<(Instant, usize)>,
    expirations: BTreeSet<(Instant, usize)>,
    unfinished: usize,
    max_attempts: u32,
    first_sequence: u64,
    host_count: usize,
    canceled_responses: usize,
    #[cfg(test)]
    discovery: usize,
    #[cfg(test)]
    ready_operations: usize,
    #[cfg(test)]
    time_operations: usize,
}

struct Slot {
    host: usize,
    endpoints: Vec<Endpoint>,
    ready: BTreeSet<usize>,
    delayed: BTreeSet<(Instant, usize)>,
    unfinished: usize,
    wake: Option<Instant>,
    expiration: Option<Instant>,
}

impl Work {
    pub(super) fn done(&self) -> bool {
        self.unfinished == 0
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Selection {
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

pub(super) struct Wave {
    pub selections: Vec<Selection>,
    pub next_ready: Option<Instant>,
    pub done: bool,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Outcome {
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

pub(super) struct Controller {
    config: Adaptive,
    initial_timeout: Duration,
    max_in_flight: usize,
    operation: Estimator,
    hosts: Vec<Host>,
    indices: HashMap<(IpAddr, Option<interface::Id>), usize>,
    window: usize,
    peak_window: usize,
    successes: usize,
    retries_started: u64,
    cohort: u64,
    halved: std::collections::HashSet<u64>,
    cohort_members: HashMap<u64, usize>,
    conditions: Vec<Condition>,
    incomplete: Vec<HostIdentity>,
    defer_conditions: bool,
}

impl Controller {
    pub(super) fn new(config: Adaptive, initial_timeout: Duration, max_in_flight: usize) -> Self {
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

    pub(super) fn window(&self) -> usize {
        self.window.min(self.max_in_flight)
    }

    fn host(&mut self, target: &SelectedAddress) -> usize {
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

    pub(super) fn host_expired(&self, host: usize, now: Instant) -> bool {
        self.hosts[host]
            .first_admission
            .is_some_and(|started| now >= started + self.config.host_timeout)
    }

    pub(super) fn host_remaining(&self, host: usize, now: Instant) -> Duration {
        match self.hosts[host].first_admission {
            Some(started) => (started + self.config.host_timeout).saturating_duration_since(now),
            None => self.config.host_timeout,
        }
    }

    pub(super) fn host_started(&mut self, host: usize, now: Instant) {
        self.hosts[host].first_admission.get_or_insert(now);
    }

    pub(super) fn host_index(&mut self, target: &SelectedAddress) -> usize {
        self.host(target)
    }

    pub(super) fn find(&self, target: &SelectedAddress) -> Option<usize> {
        self.indices.get(&target.key()).copied()
    }

    pub(super) fn is_incomplete(&self, host: usize) -> bool {
        self.hosts[host].incomplete
    }

    pub(super) fn mark_incomplete(&mut self, host: usize) {
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

    pub(super) fn open_stage(
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
                host: self.host(target),
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
            #[cfg(test)]
            discovery: 0,
            #[cfg(test)]
            ready_operations: unfinished,
            #[cfg(test)]
            time_operations: 0,
        };
        for slot in 0..work.slots.len() {
            self.refresh_slot(&mut work, slot, now);
        }
        work
    }

    pub(super) fn take_canceled_responses(&self, work: &mut Work) -> usize {
        std::mem::take(&mut work.canceled_responses)
    }

    /// Replaces a slot's single wake/expiry index entries. No stale heap
    /// entries accumulate across retries, pacing changes, or stage completion.
    fn refresh_slot(&self, work: &mut Work, index: usize, now: Instant) {
        let slot = &mut work.slots[index];
        work.runnable.remove(&index);
        #[cfg(test)]
        {
            work.ready_operations += 1;
        }
        if let Some(wake) = slot.wake.take() {
            work.wakes.remove(&(wake, index));
            #[cfg(test)]
            {
                work.time_operations += 1;
            }
        }
        if let Some(expiration) = slot.expiration.take() {
            work.expirations.remove(&(expiration, index));
            #[cfg(test)]
            {
                work.time_operations += 1;
            }
        }
        if slot.unfinished == 0 {
            return;
        }
        let host = &self.hosts[slot.host];
        if let Some(started) = host.first_admission {
            let expiration = started + self.config.host_timeout;
            work.expirations.insert((expiration, index));
            #[cfg(test)]
            {
                work.time_operations += 1;
            }
            slot.expiration = Some(expiration);
        }
        if host.min_gap > Duration::ZERO && host.uncommitted > 0 {
            return;
        }
        let gap = host.last_send.map(|last| last + host.min_gap);
        let ready_time = (!slot.ready.is_empty()).then(|| gap.unwrap_or(now));
        if ready_time.is_some_and(|ready| ready <= now) {
            work.runnable.insert(index);
            #[cfg(test)]
            {
                work.ready_operations += 1;
            }
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
            #[cfg(test)]
            {
                work.time_operations += 1;
            }
            slot.wake = Some(wake);
        }
    }

    fn expire(&mut self, work: &mut Work, now: Instant) {
        while let Some((expiration, index)) = work.expirations.first().copied() {
            if expiration > now {
                break;
            }
            work.expirations.pop_first();
            #[cfg(test)]
            {
                work.time_operations += 1;
            }
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
            #[cfg(test)]
            {
                work.ready_operations += 1;
                work.time_operations += 1;
            }
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
            #[cfg(test)]
            {
                work.time_operations += 1;
            }
            let slot = &mut work.slots[index];
            slot.wake = None;
            while slot.delayed.first().is_some_and(|(ready, _)| *ready <= now) {
                let (_, endpoint) = slot.delayed.pop_first().expect("due retry exists");
                slot.ready.insert(endpoint);
                #[cfg(test)]
                {
                    work.ready_operations += 1;
                    work.time_operations += 1;
                }
            }
            self.refresh_slot(work, index, now);
        }
    }

    pub(super) fn select(
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
                #[cfg(test)]
                {
                    work.ready_operations += 1;
                }
                continue;
            };
            #[cfg(test)]
            {
                work.discovery += 1;
                work.ready_operations += 1;
            }
            held.push((slot_index, endpoint_index));
            if slot.ready.is_empty() || self.hosts[host].min_gap > Duration::ZERO {
                work.runnable.remove(&slot_index);
                #[cfg(test)]
                {
                    work.ready_operations += 1;
                }
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
                #[cfg(test)]
                {
                    work.ready_operations += 1;
                }
                suppressed.push(slot_index);
                continue;
            }
            let desired = self.rto(host);
            let timeout = desired.min(host_remaining);
            let attempt = work.slots[slot_index].endpoints[endpoint_index].sent + 1;
            let sequence = work.first_sequence.saturating_add(
                ((u64::from(attempt) - 1)
                    .saturating_mul(endpoints_per_host as u64)
                    .saturating_add(endpoint_index as u64))
                .saturating_mul(work.host_count as u64)
                .saturating_add(host as u64),
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
            #[cfg(test)]
            {
                work.ready_operations += 1;
            }
        }
        for slot in suppressed {
            work.runnable.insert(slot);
            #[cfg(test)]
            {
                work.ready_operations += 1;
            }
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

    pub(super) fn admitted(&mut self, work: &mut Work, selection: Selection) {
        let slot = &mut work.slots[selection.slot];
        slot.endpoints[selection.endpoint].pending = true;
        slot.ready.remove(&selection.endpoint);
        #[cfg(test)]
        {
            work.ready_operations += 1;
        }
        *self.cohort_members.entry(selection.cohort).or_default() += 1;
        self.host_started(selection.host, selection.selected_at);
        self.hosts[selection.host].uncommitted += 1;
        self.refresh_slot(work, selection.slot, selection.selected_at);
    }

    /// Commits an admitted slot's attempt number and paces the host from the
    /// admission time; whether a probe actually started is counted separately.
    pub(super) fn commit_attempt(
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
    pub(super) fn note_attempted(&mut self, selection: Selection) {
        if selection.attempt > 1 {
            self.retries_started = self.retries_started.saturating_add(1);
        }
    }

    pub(super) fn confirm_send(&mut self, work: &mut Work, selection: Selection, sent_at: Instant) {
        self.commit_attempt(work, selection, sent_at);
        self.note_attempted(selection);
    }

    pub(super) fn observe_active(&mut self, active: usize) {
        self.peak_window = self.peak_window.max(active);
    }

    pub(super) fn host_gap_ready(&self, host: usize, now: Instant) -> bool {
        match self.hosts[host].last_send {
            Some(last) => last + self.hosts[host].min_gap <= now,
            None => true,
        }
    }

    fn retry_delay(&self, next_attempt: u32) -> Duration {
        let shift = next_attempt.saturating_sub(2).min(31);
        self.config
            .retry_backoff
            .saturating_mul(1u32 << shift)
            .min(self.config.max_backoff)
    }

    pub(super) fn settle(
        &mut self,
        work: &mut Work,
        selection: Selection,
        outcome: Outcome,
        now: Instant,
    ) {
        let slot_index = selection.slot;
        let slot = &mut work.slots[slot_index];
        let host_index = slot.host;
        let endpoint = &mut slot.endpoints[selection.endpoint];
        let was_finished = endpoint.finished;
        let was_pending = endpoint.pending;
        if was_pending && endpoint.sent < selection.attempt {
            self.hosts[host_index].uncommitted =
                self.hosts[host_index].uncommitted.saturating_sub(1);
        }
        endpoint.pending = false;
        slot.ready.remove(&selection.endpoint);
        #[cfg(test)]
        {
            work.ready_operations += 1;
        }
        if !matches!(outcome, Outcome::Omitted) {
            self.hosts[host_index].completed = self.hosts[host_index].completed.saturating_add(1);
        }
        match outcome {
            Outcome::Reply {
                latency,
                responder,
                control,
            } => {
                endpoint.finished = true;
                let host = &mut self.hosts[host_index];
                host.replies = host.replies.saturating_add(1);
                if selection.attempt == 1 {
                    host.estimator.sample(latency);
                    self.operation.sample(latency);
                }
                if control {
                    host.control_errors = host.control_errors.saturating_add(1);
                    let responder = host.control.entry(responder).or_default();
                    responder.count = responder.count.saturating_add(1);
                    if responder.sequences.len() < CITED_SEQUENCES {
                        responder.sequences.push(selection.sequence);
                    }
                }
                self.successes = self.successes.saturating_add(1);
                if self.successes >= self.window() {
                    self.window = self.window.saturating_add(1).min(self.max_in_flight);
                    self.successes = 0;
                }
            }
            Outcome::Silent | Outcome::UnqualifiedSilence => {
                let host = &mut self.hosts[host_index];
                if matches!(outcome, Outcome::Silent) {
                    host.losses = host.losses.saturating_add(1);
                    if host.loss_sequences.len() < CITED_SEQUENCES {
                        host.loss_sequences.push(selection.sequence);
                    }
                    if self.halved.insert(selection.cohort) {
                        self.window = (self.window / 2).max(self.config.min_window);
                        self.successes = 0;
                    }
                } else {
                    host.pending_losses = host.pending_losses.saturating_add(1);
                    if host.pending_loss_sequences.len() < CITED_SEQUENCES {
                        host.pending_loss_sequences.push(selection.sequence);
                    }
                }
                if selection.attempt >= work.max_attempts {
                    endpoint.finished = true;
                } else {
                    endpoint.ready_at = now + self.retry_delay(selection.attempt + 1);
                    if !was_finished {
                        slot.delayed.insert((endpoint.ready_at, selection.endpoint));
                        #[cfg(test)]
                        {
                            work.time_operations += 1;
                        }
                    }
                }
                if selection.host_limited {
                    self.mark_incomplete(host_index);
                }
            }
            Outcome::Aborted | Outcome::Omitted => {
                if !was_finished {
                    work.canceled_responses = work
                        .canceled_responses
                        .saturating_add(work.max_attempts.saturating_sub(endpoint.sent) as usize);
                }
                endpoint.finished = true;
            }
        }
        if endpoint.finished && !was_finished {
            slot.unfinished = slot.unfinished.saturating_sub(1);
            work.unfinished = work.unfinished.saturating_sub(1);
        }
        if was_pending && let Some(remaining) = self.cohort_members.get_mut(&selection.cohort) {
            *remaining = remaining.saturating_sub(1);
            if *remaining == 0 {
                self.cohort_members.remove(&selection.cohort);
                self.halved.remove(&selection.cohort);
            }
        }
        if !self.defer_conditions {
            self.check_conditions(slot_index, host_index);
        }
        self.refresh_slot(work, slot_index, now);
    }

    /// A raw stage cannot infer a new pacing condition until its acquisition
    /// quality settles. Existing conditions still pace every admitted send.
    pub(super) fn begin_observation_stage(&mut self) {
        self.defer_conditions = true;
    }

    /// Reconciles bounded per-host provisional counters after acquisition has
    /// stopped. Raw silence cannot reduce the live stage's window before this
    /// point; a clean stage applies one loss backoff for a following stage.
    pub(super) fn qualify_pending(&mut self, coverage: super::Coverage) {
        let mut qualified_loss = false;
        for index in 0..self.hosts.len() {
            let host = &mut self.hosts[index];
            let pending = std::mem::take(&mut host.pending_losses);
            if pending == 0 {
                continue;
            }
            if coverage.permits_silence() {
                qualified_loss = true;
                host.losses = host.losses.saturating_add(pending);
                let room = CITED_SEQUENCES.saturating_sub(host.loss_sequences.len());
                host.loss_sequences
                    .extend(host.pending_loss_sequences.drain(..).take(room));
                host.pending_loss_sequences.clear();
            } else {
                host.pending_loss_sequences.clear();
                self.mark_incomplete(index);
            }
        }
        self.defer_conditions = false;
        for index in 0..self.hosts.len() {
            self.check_conditions(0, index);
        }
        if qualified_loss {
            self.window = (self.window / 2).max(self.config.min_window);
            self.successes = 0;
        }
    }

    fn check_conditions(&mut self, _slot: usize, host_index: usize) {
        let host = &self.hosts[host_index];
        if host.condition_raised
            || host.completed < INFERENCE_MIN_COMPLETED
            || host.control_errors < INFERENCE_MIN_CONTROL as u64
            || host.losses < INFERENCE_MIN_LOSSES
        {
            return;
        }
        let Some(control_responder) = host
            .control
            .iter()
            .filter(|(_, entry)| entry.count >= INFERENCE_MIN_CONTROL as u64)
            .map(|(responder, _)| *responder)
            .min()
        else {
            return;
        };
        let control_sequences = host.control[&control_responder].sequences.clone();
        let gap = self
            .rto(host_index)
            .max(self.config.retry_backoff)
            .min(self.config.max_backoff);
        let host = &mut self.hosts[host_index];
        host.condition_raised = true;
        host.min_gap = gap;
        self.conditions.push(Condition {
            kind: ConditionKind::SuspectedResponseRateLimit,
            host: HostIdentity {
                address: host.key.0,
                scope: host.scope.clone(),
            },
            control_responder,
            completed: host.completed,
            replies: host.replies,
            losses: host.losses,
            control_sequences,
            loss_sequences: host.loss_sequences.clone(),
            caveat: "inferred from control replies beside silent attempts; \
                     filtering or loss remain alternative explanations",
        });
    }

    pub(super) fn finish(self, ceilings: (Option<usize>, Option<usize>)) -> Scheduling {
        Scheduling {
            mode: SchedulingMode::Adaptive,
            adaptive: Some(self.config),
            observed_peak_window: self.peak_window,
            retries_started: self.retries_started,
            conditions: self.conditions,
            incomplete: self.incomplete,
            operation_ceiling: ceilings.0,
            process_ceiling: ceilings.1,
        }
    }
}

pub(super) fn state_charge(
    host_count: usize,
    endpoints_per_host: usize,
    pending_bound: usize,
    scoped_bytes: usize,
    shared_bytes: usize,
) -> usize {
    let host = std::mem::size_of::<Host>()
        .saturating_add(2usize.saturating_mul(std::mem::size_of::<HostIdentity>()))
        .saturating_add(std::mem::size_of::<Condition>())
        .saturating_add(std::mem::size_of::<(IpAddr, Option<interface::Id>)>())
        .saturating_add(std::mem::size_of::<usize>())
        .saturating_add(
            CITED_SEQUENCES
                .saturating_mul(3)
                .saturating_mul(std::mem::size_of::<u64>()),
        );
    // Reserve conservative B-tree node/allocation slack for the mutually
    // exclusive endpoint ready/retry entries and the three per-slot indexes.
    // Replacement removes old entries; retries never leave stale index state.
    let slot = std::mem::size_of::<Slot>()
        .saturating_add(384)
        .saturating_add(
            endpoints_per_host.saturating_mul(std::mem::size_of::<Endpoint>().saturating_add(192)),
        );
    let hosts = host_count
        .saturating_mul(host.saturating_add(slot).saturating_mul(2))
        .saturating_add(
            host_count
                .saturating_mul(endpoints_per_host)
                .saturating_mul(4)
                .saturating_mul(
                    std::mem::size_of::<(IpAddr, ControlResponder)>()
                        .saturating_add(CITED_SEQUENCES.saturating_mul(std::mem::size_of::<u64>())),
                ),
        );
    let live = pending_bound.saturating_mul(2).saturating_mul(
        std::mem::size_of::<u64>()
            .saturating_add(std::mem::size_of::<usize>())
            .saturating_add(std::mem::size_of::<Selection>()),
    );
    std::mem::size_of::<Controller>()
        .saturating_add(std::mem::size_of::<Work>())
        .saturating_add(hosts)
        .saturating_add(live)
        .saturating_add(scoped_bytes.saturating_mul(8))
        .saturating_add(shared_bytes)
}

pub(super) fn scoped_bytes(targets: &[SelectedAddress]) -> usize {
    targets.iter().fold(0usize, |bytes, target| {
        bytes.saturating_add(target.scope_bytes())
    })
}

pub(super) fn fixed_scheduling(
    ceilings: (Option<usize>, Option<usize>),
    peak: usize,
    retries_started: usize,
) -> Scheduling {
    Scheduling {
        mode: SchedulingMode::Fixed,
        adaptive: None,
        observed_peak_window: peak,
        retries_started: retries_started as u64,
        conditions: Vec::new(),
        incomplete: Vec::new(),
        operation_ceiling: ceilings.0,
        process_ceiling: ceilings.1,
    }
}

#[cfg(test)]
#[path = "adaptive/tests.rs"]
mod tests;
