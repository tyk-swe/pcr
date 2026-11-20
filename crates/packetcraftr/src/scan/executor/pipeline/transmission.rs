// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
//! Queued probe transmission and wake scheduling.

use super::{Pipeline, check, limit, max_wait_secs};
use crate::{
    clock::Clock, engine::preparation::RebuildError, providers::PacketProviders,
    scan::executor::PipelineEvent,
};
use packetcraftr_core::error::BoundaryError;
use packetcraftr_netio::{Error as LiveIoError, capture};
use std::{sync::Arc, time::Instant};

impl<P: PacketProviders, K: Clock> Pipeline<'_, P, K> {
    pub(super) fn send_ready(&mut self, draining_captures: bool) -> Result<(), BoundaryError> {
        let now = self.executor.client.now();
        while let Some(index) = self.attempts.next_expired_ready(now) {
            self.omit(index)?;
        }
        self.rotate_if_needed()?;
        while !draining_captures
            && self.attempts.pending_count() < self.options.max_in_flight
            && self.executor.client.now() >= self.next_send
        {
            let Some(index) = self
                .attempts
                .armed_indices()
                .find(|index| !self.attempts.reply_overlaps(*index))
            else {
                break;
            };
            while self
                .attempts
                .retained()
                .saturating_add(self.attempts.queued_memory(index))
                > self.options.max_prepared_bytes
                && self.attempts.retire_recent()
            {}
            if self
                .attempts
                .retained()
                .saturating_add(self.attempts.queued_memory(index))
                > self.options.max_prepared_bytes
            {
                break;
            }
            self.send(index)?;
            if !self.spacing.is_zero() {
                break;
            }
        }
        Ok(())
    }

    fn omit(&mut self, index: usize) -> Result<(), BoundaryError> {
        self.failed_probe = None;
        self.attempts.omit(index);
        self.output.event(PipelineEvent::Omitted { index })?;
        if let Some(stream) = &mut self.streaming {
            stream.next_ready = None;
        }
        Ok(())
    }

    fn send(&mut self, index: usize) -> Result<(), BoundaryError> {
        let client = self.executor.client;
        check(client, self.deadline, &self.options.control)?;
        let host_deadline = self.attempts.description(index).host_deadline;
        if host_deadline.is_some_and(|limit| client.now() >= limit) {
            return self.omit(index);
        }
        self.failed_probe = Some(self.attempts.description(index).probe().clone());
        let (prepared, memory) = self.attempts.prepare(index, |descriptor, admitted| {
            let probe = descriptor.probe();
            let route = descriptor.route.as_deref().unwrap_or_else(|| {
                &self.plan.routes[&(
                    probe.address,
                    probe.scope.as_ref().map(|scope| scope.interface.clone()),
                )]
            });
            match admitted.retained {
                Some(retained) => {
                    self.plan
                        .admission
                        .materialize_retained(retained, route, admitted.cost)
                }
                None => self.plan.admission.rebuild(
                    probe.packet(&self.executor.operation.registry),
                    route,
                    admitted.cost,
                ),
            }
        });
        let descriptor = self.attempts.description(index);
        let timeout = descriptor.batch.batch().timeout;
        let probe = self.failed_probe.as_ref().expect("sending probe");
        let prepared = prepared.map_err(|error| match error {
            RebuildError::Changed { admitted } => limit("changed preparation size", admitted),
            RebuildError::Preparation(source) => BoundaryError::from_error(source),
        })?;
        if !crate::scan::plan::packet::sent_probe_matches(
            &self.executor.operation.registry,
            probe,
            &prepared.built().packet,
        ) {
            return Err(BoundaryError::internal_execution(
                "materialized scan packet differs from its probe",
                packetcraftr_core::error::Code::InternalScanProbeMismatch,
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
                .transmit(self.transmitter.as_ref(), || Ok::<(), LiveIoError>(()))
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
        self.attempts.record_sent(
            index,
            source,
            sent.clone(),
            end,
            memory,
            &self.executor.operation.registry,
        )?;
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
            .attempts
            .next_deadline()
            .unwrap_or(self.deadline)
            .min(self.deadline);
        if let Some(deadline) = self.attempts.next_ready_deadline() {
            earliest = earliest.min(deadline);
        }
        let can_send = self.attempts.pending_count() < self.options.max_in_flight
            && self
                .attempts
                .armed_indices()
                .find(|index| !self.attempts.reply_overlaps(*index))
                .is_some_and(|index| {
                    self.attempts
                        .retained()
                        .saturating_add(self.attempts.queued_memory(index))
                        <= self.options.max_prepared_bytes
                });
        let can_refill = self.streaming.as_ref().is_some_and(|stream| {
            !stream.done
                && self
                    .attempts
                    .pending_count()
                    .saturating_add(self.attempts.queued_count())
                    < self.options.max_in_flight
                && self
                    .attempts
                    .retained()
                    .saturating_add(stream.max_probe_bytes)
                    <= self.options.max_prepared_bytes
        });
        if can_send {
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
