// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
//! Queued probe transmission and wake scheduling.

use super::{Pending, Pipeline, check, limit, max_wait_secs, prepare::AdmittedProbe};
use crate::{
    clock::Clock,
    preparation::RebuildError,
    providers::PacketProviders,
    scan::{executor::PipelineEvent, plan::replies_overlap},
};
use packetcraftr_core::error::BoundaryError;
use packetcraftr_netio::{Error as LiveIoError, capture};
use std::{sync::Arc, time::Instant};

impl<P: PacketProviders, K: Clock> Pipeline<'_, P, K> {
    pub(super) fn send_ready(&mut self, draining_captures: bool) -> Result<(), BoundaryError> {
        let now = self.executor.client.now();
        while self
            .ready_deadlines
            .first()
            .is_some_and(|(deadline, _)| *deadline <= now)
        {
            let (_, index) = self
                .ready_deadlines
                .pop_first()
                .expect("due queued attempt");
            if let Some(admitted) = self.ready.remove(&index) {
                self.armed_ready.remove(&index);
                let preview = if admitted.retained.is_some() {
                    admitted.memory
                } else {
                    0
                };
                drop(admitted);
                self.retained -= preview;
                self.omit(index)?;
            }
        }
        self.rotate_if_needed()?;
        while !draining_captures
            && self.pending.len() < self.options.max_in_flight
            && self.executor.client.now() >= self.next_send
        {
            let Some(index) = self
                .armed_ready
                .iter()
                .copied()
                .find(|index| !self.reply_overlaps(*index))
            else {
                break;
            };
            while self.ready.get(&index).is_some_and(|probe| {
                self.retained.saturating_add(probe.memory) > self.options.max_prepared_bytes
            }) && self.retire_recent()
            {}
            if self.retained.saturating_add(self.ready[&index].memory)
                > self.options.max_prepared_bytes
            {
                break;
            }
            let admitted = self.ready.remove(&index).expect("armed attempt is queued");
            self.armed_ready.remove(&index);
            if let Some(deadline) = self.descriptions[&index].host_deadline {
                self.ready_deadlines.remove(&(deadline, index));
            }
            self.send(index, admitted)?;
            if !self.spacing.is_zero() {
                break;
            }
        }
        Ok(())
    }

    fn reply_overlaps(&self, index: usize) -> bool {
        let next = self.descriptions[&index].probe();
        self.pending
            .keys()
            .any(|pending| replies_overlap(next, self.descriptions[pending].probe()))
    }

    fn omit(&mut self, index: usize) -> Result<(), BoundaryError> {
        self.failed_probe = None;
        self.retire_description(index);
        self.output.event(PipelineEvent::Omitted { index })?;
        if let Some(stream) = &mut self.streaming {
            stream.next_ready = None;
        }
        Ok(())
    }

    fn send(
        &mut self,
        index: usize,
        AdmittedProbe {
            cost,
            memory,
            retained,
        }: AdmittedProbe,
    ) -> Result<(), BoundaryError> {
        let client = self.executor.client;
        check(client, self.deadline, &self.options.control)?;
        let preview_bytes = if retained.is_some() { memory } else { 0 };
        let host_deadline = self.descriptions[&index].host_deadline;
        if host_deadline.is_some_and(|limit| client.now() >= limit) {
            drop(retained);
            self.retained -= preview_bytes;
            return self.omit(index);
        }
        let descriptor = &self.descriptions[&index];
        let timeout = descriptor.batch.batch().timeout;
        let probe = descriptor.probe();
        self.failed_probe = Some(probe.clone());
        let route = descriptor.route.as_deref().unwrap_or_else(|| {
            &self.plan.routes[&(
                probe.address,
                probe.scope.as_ref().map(|scope| scope.interface.clone()),
            )]
        });
        let prepared = match retained {
            Some(retained) => self
                .plan
                .admission
                .materialize_retained(retained, route, cost),
            None => self.plan.admission.rebuild(probe.packet(), route, cost),
        };
        self.retained -= preview_bytes;
        let prepared = prepared.map_err(|error| match error {
            RebuildError::Changed { admitted } => limit("changed preparation size", admitted),
            RebuildError::Preparation(source) => BoundaryError::from_error(source),
        })?;
        if !crate::scan::plan::packet::sent_probe_matches(probe, &prepared.built().packet) {
            return Err(BoundaryError::internal_execution(
                "materialized scan packet differs from its probe",
                "internal.scan_probe_mismatch",
                "preserve the planned endpoint and identity",
            ));
        }
        check(client, self.deadline, &self.options.control)?;
        if host_deadline.is_some_and(|limit| client.now() >= limit) {
            drop(prepared);
            return self.omit(index);
        }
        self.stats.packets_attempted += 1;
        let sent = Arc::new(
            prepared
                .transmit(client.providers.transmit(), || Ok::<(), LiveIoError>(()))
                .map_err(BoundaryError::from_error)?,
        );
        self.stats.packets_completed += 1;
        self.history.sent(
            probe,
            &sent.built().packet,
            &sent.route().plan.decision.interface,
        );
        self.stats.bytes = self
            .stats
            .bytes
            .checked_add(sent.bytes_sent() as u64)
            .ok_or_else(|| limit("sent bytes", usize::MAX))?;
        let end = sent
            .timing()
            .freshness_marker()
            .monotonic()
            .checked_add(timeout)
            .ok_or_else(|| limit("probe timeout", max_wait_secs()))?
            .min(self.deadline);
        let end = host_deadline.map_or(end, |limit| end.min(limit));
        let source = self
            .plan
            .interfaces
            .iter()
            .position(|interface| *interface == sent.route().plan.decision.interface)
            .ok_or_else(|| limit("changed capture interface", capture::MAX_SOURCES))?;
        self.candidates.insert(
            index,
            source,
            &sent.built().packet,
            &self.executor.operation.registry,
        )?;
        self.deadlines.insert(end, index);
        self.pending.insert(
            index,
            Pending {
                sent: sent.clone(),
                deadline: end,
                best: None,
                passed: Vec::new(),
                last_response: None,
                charge: memory,
            },
        );
        self.retained += memory;
        self.output.event(PipelineEvent::Sent { index, sent })?;
        self.qualification = Some(match self.qualification {
            Some((stage, first, last)) => {
                (stage, first.min(probe.sequence), last.max(probe.sequence))
            }
            None => (probe.stage, probe.sequence, probe.sequence),
        });
        self.failed_probe = None;
        self.next_send = client
            .now()
            .checked_add(self.spacing)
            .ok_or_else(|| limit("pacing delay", max_wait_secs()))?;
        Ok(())
    }

    pub(super) fn wake_time(&mut self) -> Instant {
        let mut earliest = self
            .deadlines
            .next()
            .unwrap_or(self.deadline)
            .min(self.deadline);
        if let Some((deadline, _)) = self.ready_deadlines.first() {
            earliest = earliest.min(*deadline);
        }
        let can_send = self
            .armed_ready
            .iter()
            .copied()
            .find(|index| !self.reply_overlaps(*index))
            .is_some_and(|index| {
                self.retained.saturating_add(self.ready[&index].memory)
                    <= self.options.max_prepared_bytes
            });
        let can_refill = self.streaming.as_ref().is_some_and(|stream| {
            !stream.done
                && self.pending.len().saturating_add(self.ready.len()) < self.options.max_in_flight
                && self.retained.saturating_add(stream.max_probe_bytes)
                    <= self.options.max_prepared_bytes
        });
        if self.pending.len() < self.options.max_in_flight && can_send {
            earliest = earliest.min(self.next_send);
        }
        if can_refill {
            let ready = self
                .streaming
                .as_ref()
                .and_then(|stream| stream.next_ready)
                .unwrap_or(self.next_send)
                .max(self.next_send);
            earliest = earliest.min(ready);
        }
        earliest
    }
}
