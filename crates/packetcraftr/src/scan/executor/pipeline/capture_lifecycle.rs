// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
//! One capture source set, from activation through final accounting.

use super::correlation::SeenFrames;
use super::{CaptureSession, Pipeline, check, until};
use crate::{clock::Clock, exchange::WorkflowExecutor, providers::PacketProviders};
use packetcraftr_core::{budget::Deadline, error::BoundaryError};
use packetcraftr_netio::{
    Error as LiveIoError,
    capture::{self, Group, GroupRequest, RecordIdentity, Session as _},
    interface,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub(super) struct CaptureEpoch<'a, P: PacketProviders, K> {
    executor: &'a WorkflowExecutor<'a, P, K>,
    control: Deadline,
    deadline: Instant,
    group: Group<CaptureSession<P>>,
    interfaces: Vec<interface::Id>,
    pub(in crate::scan::executor::pipeline) drain: CaptureDrain,
    accounted: bool,
    aggregate_quality: capture::ObservationQuality,
    seen: SeenFrames,
    max_evidence_frames: usize,
}

pub(super) struct CaptureDrain {
    limit: usize,
    remaining: usize,
}

impl CaptureDrain {
    fn new<C: capture::Session>(group: &Group<C>) -> Self {
        let limit = group
            .sources()
            .map(|source| source.limits.max_frames)
            .max()
            .expect("validated capture group contains a source")
            * group.sources().len();
        Self {
            limit,
            remaining: limit,
        }
    }

    pub(super) fn reset(&mut self) {
        self.remaining = self.limit;
    }

    pub(super) fn active(&self, expired: bool) -> bool {
        expired && self.remaining > 0
    }
}

type Account<'a> = dyn FnMut(bool, &[capture::Source]) -> Result<(), BoundaryError> + 'a;

pub(super) struct CaptureClose {
    pub(super) shutdown: Option<LiveIoError>,
    pub(super) accounted: Result<(), BoundaryError>,
    pub(super) sources: Vec<capture::Source>,
    pub(super) quality: capture::ObservationQuality,
}

impl<'a, P: PacketProviders, K: Clock> CaptureEpoch<'a, P, K> {
    pub(super) fn open(
        executor: &'a WorkflowExecutor<'a, P, K>,
        interfaces: Vec<interface::Id>,
        deadline: Instant,
        control: &Deadline,
        max_evidence_frames: usize,
    ) -> Result<Self, BoundaryError> {
        let request = GroupRequest::new(interfaces.clone(), executor.collection.capture);
        let mut group = Group::new(&request).map_err(BoundaryError::from_error)?;
        let armed = group.arm(
            executor.client.providers.capture(),
            &until(executor.client, deadline, control),
        );
        check(executor.client, deadline, control)?;
        armed.map_err(BoundaryError::from_error)?;
        let drain = CaptureDrain::new(&group);
        Ok(Self {
            executor,
            control: control.clone(),
            deadline,
            group,
            interfaces,
            drain,
            accounted: false,
            aggregate_quality: capture::ObservationQuality::NoReportedLoss,
            seen: SeenFrames::new(max_evidence_frames),
            max_evidence_frames,
        })
    }

    pub(super) fn source_count(&self) -> usize {
        self.interfaces.len()
    }

    pub(super) fn source(&self, index: usize) -> &interface::Id {
        &self.interfaces[index]
    }

    pub(super) fn contains(&self, interface: &interface::Id) -> bool {
        self.interfaces.contains(interface)
    }

    pub(super) fn deduplicate(&mut self, identity: RecordIdentity) -> bool {
        self.seen.insert(identity)
    }

    pub(super) fn ready(&mut self) -> Result<(), BoundaryError> {
        let ready =
            self.group
                .wait_ready(&until(self.executor.client, self.deadline, &self.control));
        self.check()?;
        ready.map_err(BoundaryError::from_error)
    }

    pub(super) fn read_frame(
        &mut self,
        wake: Instant,
        draining: bool,
    ) -> Result<Option<capture::Captured>, BoundaryError> {
        let mut wait = wake
            .saturating_duration_since(self.executor.client.now())
            .min(Duration::from_millis(5));
        if draining {
            self.drain.remaining -= 1;
            wait = Duration::ZERO;
        }
        let wait = Deadline::new(wait)
            .with_cancellation(self.executor.client.cancellation.clone())
            .with_parent(Some(Arc::new(self.control.clone())));
        let captured = self.group.next_captured_frame(&wait);
        self.check()?;
        let captured = captured.map_err(BoundaryError::from_error)?;
        if captured.is_none() && draining {
            self.drain.remaining = 0;
        }
        Ok(captured)
    }

    fn check(&self) -> Result<(), BoundaryError> {
        check(self.executor.client, self.deadline, &self.control)
    }

    fn close(&mut self, publish: bool, account: &mut Account<'_>) -> Result<(), BoundaryError> {
        if self.accounted {
            return Ok(());
        }
        let shutdown = self.group.shutdown().map_err(BoundaryError::from_error);
        let accounted = self.account(publish && shutdown.is_ok(), account);
        shutdown.and(accounted)
    }

    fn account(&mut self, publish: bool, account: &mut Account<'_>) -> Result<(), BoundaryError> {
        if self.accounted {
            return Ok(());
        }
        let sources = self.group.snapshot();
        self.accounted = true;
        for source in &sources {
            self.aggregate_quality = self.aggregate_quality.combine(source.observation_quality);
        }
        account(publish, &sources)
    }

    pub(super) fn rotate(
        &mut self,
        interfaces: Vec<interface::Id>,
        pending: usize,
        account: &mut Account<'_>,
    ) -> Result<(), BoundaryError> {
        debug_assert_eq!(pending, 0, "active probes cannot cross capture epochs");
        self.close(true, account)?;
        let request = GroupRequest::new(interfaces.clone(), self.executor.collection.capture);
        let group = Group::new(&request).map_err(BoundaryError::from_error)?;
        self.group = group;
        self.interfaces = interfaces;
        self.accounted = false;
        self.seen = SeenFrames::new(self.max_evidence_frames);
        let armed = self.group.arm(
            self.executor.client.providers.capture(),
            &until(self.executor.client, self.deadline, &self.control),
        );
        self.check()?;
        armed.map_err(BoundaryError::from_error)?;
        self.ready()?;
        self.drain = CaptureDrain::new(&self.group);
        Ok(())
    }

    pub(super) fn finish(mut self, publish: bool, account: &mut Account<'_>) -> CaptureClose {
        let shutdown = if self.accounted {
            None
        } else {
            self.group.shutdown().err()
        };
        let accounted = self.account(publish && shutdown.is_none(), account);
        CaptureClose {
            shutdown,
            accounted,
            sources: self.group.snapshot(),
            quality: self.aggregate_quality,
        }
    }
}

impl<P: PacketProviders, K: Clock> Pipeline<'_, P, K> {
    pub(super) fn rotate_if_needed(&mut self) -> Result<(), BoundaryError> {
        // Fixed pipelines arm every source up front; their ready queue can span
        // the whole stage, so rediscovering rotations here would be quadratic.
        if self.streaming.is_none() {
            return Ok(());
        }
        let changes = self.attempts.queued_indices().any(|index| {
            self.attempts
                .description(index)
                .route
                .as_ref()
                .is_some_and(|route| !self.capture.contains(route.interface()))
        });
        if !changes {
            return Ok(());
        }
        // Every active interval finishes in its original capture epoch. Only
        // unstarted work crosses the rearm boundary, so no negative interval
        // spans an unobserved cleanup/activation gap.
        if self.attempts.pending_count() != 0 {
            return Ok(());
        }
        while self.attempts.retire_recent() {}
        let mut interfaces =
            Vec::with_capacity(self.options.max_in_flight.min(capture::MAX_SOURCES));
        for index in self.attempts.queued_indices() {
            let descriptor = &self.attempts.description(index);
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
        self.capture.rotate(
            interfaces.clone(),
            self.attempts.pending_count(),
            &mut |publish, sources| {
                Self::account_capture(&mut self.stats, &mut self.output, publish, sources)
            },
        )?;
        self.plan.interfaces = interfaces;
        self.attempts.begin_epoch(self.capture.source_count());
        Ok(())
    }
}
