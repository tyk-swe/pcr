// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Settling attempts: attributing replies and losses to hosts, and inferring
//! the pacing conditions that loss beside control replies suggests.

use std::time::Instant;

use super::{CITED_SEQUENCES, Controller, Outcome};
use crate::scan::adaptive::work::{Selection, Work};
use crate::scan::adaptive::{Condition, ConditionKind, HostIdentity};

const INFERENCE_MIN_COMPLETED: u64 = 8;
const INFERENCE_MIN_CONTROL: usize = 2;
const INFERENCE_MIN_LOSSES: u64 = 4;

impl Controller {
    pub(in crate::scan) fn settle(
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
        work.operations.ready();
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
                    endpoint.ready_at = now + self.config.retry_delay(selection.attempt + 1);
                    if !was_finished {
                        slot.delayed.insert((endpoint.ready_at, selection.endpoint));
                        work.operations.time();
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
            self.check_conditions(host_index);
        }
        self.refresh_slot(work, slot_index, now);
    }

    /// A raw stage cannot infer a new pacing condition until its acquisition
    /// quality settles. Existing conditions still pace every admitted send.
    pub(in crate::scan) fn begin_observation_stage(&mut self) {
        self.defer_conditions = true;
    }

    /// Reconciles bounded per-host provisional counters after acquisition has
    /// stopped. Raw silence cannot reduce the live stage's window before this
    /// point; a clean stage applies one loss backoff for a following stage.
    pub(in crate::scan) fn qualify_pending(&mut self, coverage: crate::scan::Coverage) {
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
            self.check_conditions(index);
        }
        if qualified_loss {
            self.window = (self.window / 2).max(self.config.min_window);
            self.successes = 0;
        }
    }

    fn check_conditions(&mut self, host_index: usize) {
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
}
