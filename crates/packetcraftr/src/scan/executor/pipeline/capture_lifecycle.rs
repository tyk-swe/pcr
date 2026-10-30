// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
//! Capture epoch rotation, accounting, and bounded reads.

use super::correlation::{CandidateIndex, SeenFrames};
use super::{Pipeline, check, limit, until};
use crate::{clock::Clock, providers::PacketProviders, scan::executor::PipelineEvent};
use packetcraftr_core::{
    budget::Deadline,
    diagnostic::{Diagnostic, Severity},
    error::BoundaryError,
};
use packetcraftr_netio::capture::{self, Group, GroupRequest, Session as _};
use std::{sync::Arc, time::Duration};

impl<P: PacketProviders, K: Clock> Pipeline<'_, P, K> {
    pub(super) fn rotate_if_needed(&mut self) -> Result<(), BoundaryError> {
        // Fixed pipelines arm every source up front; their ready queue can span
        // the whole stage, so rediscovering rotations here would be quadratic.
        if self.streaming.is_none() {
            return Ok(());
        }
        let changes = self.ready.iter().any(|(index, _)| {
            self.descriptions[index]
                .route
                .as_ref()
                .is_some_and(|route| !self.plan.interfaces.contains(route.interface()))
        });
        if !changes {
            return Ok(());
        }
        // Every active interval finishes in its original capture epoch. Only
        // unstarted work crosses the rearm boundary, so no negative interval
        // spans an unobserved cleanup/activation gap.
        if !self.pending.is_empty() {
            return Ok(());
        }
        self.close_group()?;
        while self.retire_recent() {}
        let mut interfaces =
            Vec::with_capacity(self.options.max_in_flight.min(capture::MAX_SOURCES));
        for index in self.ready.keys() {
            let descriptor = &self.descriptions[index];
            let probe = descriptor.probe();
            let route = descriptor.route.as_deref().unwrap_or_else(|| {
                &self.plan.routes[&(
                    probe.address,
                    probe.scope.as_ref().map(|scope| scope.interface.clone()),
                )]
            });
            if !interfaces.contains(route.interface()) {
                interfaces.push(route.interface().clone());
            }
        }
        let request = GroupRequest {
            interfaces: interfaces.clone(),
            limits: self.executor.collection.capture,
            filter: None,
            promiscuous: false,
            native: Default::default(),
        };
        let group = Group::new(&request).map_err(BoundaryError::from_error)?;
        self.plan.interfaces = interfaces;
        self.group = group;
        self.group_accounted = false;
        let armed = self.group.arm(
            self.executor.client.providers.capture(),
            &until(self.executor.client, self.deadline, &self.options.control),
        );
        check(self.executor.client, self.deadline, &self.options.control)?;
        armed.map_err(BoundaryError::from_error)?;
        let ready = self.group.wait_ready(&until(
            self.executor.client,
            self.deadline,
            &self.options.control,
        ));
        check(self.executor.client, self.deadline, &self.options.control)?;
        ready.map_err(BoundaryError::from_error)?;
        self.armed_ready = self.ready.keys().copied().collect();
        self.capture_drain_limit = self
            .group
            .sources()
            .map(|source| source.limits.max_frames)
            .max()
            .expect("validated capture sources")
            * self.group.sources().len();
        self.capture_drain_remaining = self.capture_drain_limit;
        self.seen = SeenFrames::new(self.options.max_evidence_frames);
        self.candidates = CandidateIndex::new(
            self.plan.interfaces.len(),
            self.options.max_in_flight.saturating_mul(2),
        );
        Ok(())
    }

    fn close_group(&mut self) -> Result<(), BoundaryError> {
        if self.group_accounted {
            return Ok(());
        }
        let shutdown = self.group.shutdown().map_err(BoundaryError::from_error);
        let accounted = self.account_group(shutdown.is_ok());
        shutdown.and(accounted)
    }

    pub(super) fn account_group(&mut self, publish: bool) -> Result<(), BoundaryError> {
        if self.group_accounted {
            return Ok(());
        }
        let sources = self.group.snapshot();
        self.group_accounted = true;
        for source in &sources {
            self.stats.capture = self
                .stats
                .capture
                .checked_add(source.statistics)
                .ok_or_else(|| limit("capture statistics", usize::MAX))?;
            self.aggregate_quality = self.aggregate_quality.combine(source.observation_quality);
        }
        if !publish {
            return Ok(());
        }
        for source in sources {
            if let Some(loss) = source.statistics.evidence_loss_error() {
                if source.limits.overflow_policy == capture::OverflowPolicy::Fail {
                    return Err(BoundaryError::from_error(loss));
                }
                self.output
                    .event(PipelineEvent::Diagnostic(Diagnostic::new(
                        Severity::Warning,
                        "capture.evidence_incomplete",
                        format!(
                            "source {} on interface {} (index {}): {loss}",
                            source.index,
                            source.metadata.interface.name,
                            source.metadata.interface.index
                        ),
                    )))?;
            }
        }
        Ok(())
    }

    pub(super) fn read_frame(
        &mut self,
        draining_captures: bool,
    ) -> Result<Option<capture::Captured>, BoundaryError> {
        let wake = self.wake_time();
        let mut wait = wake
            .saturating_duration_since(self.executor.client.now())
            .min(Duration::from_millis(5));
        if draining_captures {
            self.capture_drain_remaining -= 1;
            wait = Duration::ZERO;
        }
        let wait = Deadline::new(wait)
            .with_cancellation(self.executor.client.cancellation.clone())
            .with_parent(Some(Arc::new(self.options.control.clone())));
        let captured = self.group.next_captured_frame(&wait);
        check(self.executor.client, self.deadline, &self.options.control)?;
        let captured = captured.map_err(BoundaryError::from_error)?;
        if captured.is_none() && draining_captures {
            self.capture_drain_remaining = 0;
        }
        Ok(captured)
    }
}
