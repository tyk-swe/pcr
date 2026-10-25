// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
//! Controller-fed preparation within the pipeline's bounded active window.

use super::admission::source_charge;
use super::{
    AdaptiveAdmission, BatchStorage, Descriptor, InitialState, Output, Pipeline, Planned,
    Streaming, check, correlation, expiry, limit, max_wait_secs, prepare, until,
};
use crate::{
    Stats,
    clock::Clock,
    exchange::WorkflowExecutor,
    providers::PacketProviders,
    scan::{
        error::probe_error,
        executor::{PipelineFeed, PipelineOptions},
    },
};
use packetcraftr_core::error::BoundaryError;
use packetcraftr_netio::capture;
use std::time::Duration;

/// One capture/correlation lifetime for controller-driven raw work. Initial
/// preparation is bounded by the live window; the controller supplies later
/// attempts only after settlements release capacity.
pub(in crate::scan::executor) fn run_stream<P: PacketProviders, K: Clock>(
    executor: &WorkflowExecutor<'_, P, K>,
    options: PipelineOptions,
    admission: &AdaptiveAdmission,
    attempts: usize,
    feed: &mut dyn PipelineFeed,
    history: &mut crate::scan::executor::reply_history::ReplyHistory,
) -> Result<Stats, BoundaryError> {
    let mut options = options;
    options.max_in_flight = options.max_in_flight.min(admission.window.max(1));
    if admission.many_interfaces {
        options.max_in_flight = options.max_in_flight.min(capture::MAX_SOURCES);
    }
    let started = executor.client.now();
    let deadline = started
        .checked_add(options.max_duration)
        .ok_or_else(|| limit("duration", max_wait_secs()))?;
    let preparation = until(executor.client, deadline, &options.control);
    let initial = loop {
        check(executor.client, deadline, &options.control)?;
        let poll = feed.poll(options.max_in_flight, executor.client.now())?;
        if !poll.batches.is_empty() {
            break poll;
        }
        if poll.done {
            return Ok(Stats {
                elapsed: executor.client.now().saturating_duration_since(started),
                ..Stats::default()
            });
        }
        let wait = poll
            .next_ready
            .map_or(Duration::from_millis(1), |ready| {
                ready.saturating_duration_since(executor.client.now())
            })
            .min(Duration::from_millis(5));
        executor
            .client
            .clock
            .sleep(wait, &preparation)
            .map_err(|source| {
                BoundaryError::from_error(probe_error(
                    0,
                    crate::error::Failure::Clock(Box::new(source)),
                ))
            })?;
    };
    if initial.batches.len() > options.max_in_flight
        || attempts == 0
        || attempts > crate::scan::MAX_PROBES
    {
        return Err(limit("stream attempts", crate::scan::MAX_PROBES));
    }
    for (index, offered) in initial.batches.iter().enumerate() {
        if offered.index != index {
            return Err(limit("stream attempt identity", crate::scan::MAX_PROBES));
        }
        let _ = offered.batch.probe()?;
    }
    let planned = initial
        .batches
        .iter()
        .map(|offer| Planned::new(&offer.batch))
        .collect::<Result<Vec<_>, _>>()?;
    let mut plan = prepare::plan_with_limit(
        executor,
        &planned,
        &options,
        deadline,
        &preparation,
        true,
        attempts,
    )?;
    let old_sources = plan.interfaces.len();
    let descriptions_charge = planned
        .iter()
        .map(|planned| {
            384usize.saturating_add(
                planned
                    .probe
                    .scope
                    .as_ref()
                    .map_or(0, crate::target::ResolvedZone::retained_bytes),
            )
        })
        .sum::<usize>();
    let old_indexes = correlation::index_charge(
        planned.len().min(options.max_in_flight.saturating_mul(2)),
        old_sources,
    )
    .saturating_add(expiry::charge(planned.len().min(options.max_in_flight)));
    plan.base_bytes = plan
        .base_bytes
        .checked_sub(
            descriptions_charge
                .saturating_add(old_indexes)
                .saturating_add(plan.interfaces_bytes),
        )
        .ok_or_else(|| limit("prepared accounting", options.max_prepared_bytes))?;
    let descriptor_bytes = admission
        .max_description_bytes
        .saturating_add(admission.max_route_bytes)
        .saturating_add(512);
    let source_ceiling = options.max_in_flight.min(capture::MAX_SOURCES);
    let source_bytes = source_charge(
        source_ceiling,
        admission.max_source_name_bytes,
        admission.source_metadata_bytes,
    );
    if plan
        .interfaces
        .iter()
        .any(|interface| interface.name.len() > admission.max_source_name_bytes)
        || plan
            .routes
            .values()
            .any(|route| prepare::route_charge(route) > admission.max_route_bytes)
        || plan
            .probes
            .iter()
            .any(|probe| probe.memory > admission.max_probe_bytes)
    {
        return Err(limit(
            "changed prepared descriptions",
            options.max_prepared_bytes,
        ));
    }
    plan.base_bytes = plan
        .base_bytes
        .saturating_add(
            descriptor_bytes
                .saturating_mul(options.max_in_flight)
                .saturating_mul(2),
        )
        .saturating_add(correlation::index_charge(
            options.max_in_flight.saturating_mul(2),
            source_ceiling,
        ))
        .saturating_add(expiry::charge(options.max_in_flight))
        .saturating_add(source_bytes)
        .saturating_add(admission.summary_bytes);
    // Previews are optional. Drop them before refusing the minimum runtime
    // profile, while keeping one preflight-sized preparation overlap reserved.
    for probe in plan.probes.iter_mut().rev() {
        if plan.base_bytes.saturating_add(admission.max_probe_bytes) <= options.max_prepared_bytes {
            break;
        }
        if let Some(preview) = probe.retained.take() {
            drop(preview);
            plan.base_bytes -= probe.memory;
        }
    }
    if plan.base_bytes.saturating_add(admission.max_probe_bytes) > options.max_prepared_bytes {
        return Err(limit("prepared descriptions", options.max_prepared_bytes));
    }
    // Eagerly arm a complete source set only within the stage's active data
    // allocation. Larger source sets use bounded, drained capture epochs.
    if !admission.many_interfaces && admission.interfaces.len() <= source_ceiling {
        // Preflight sources are acquisition hints, not current route authority.
        // Include every freshly admitted source before deciding whether the
        // complete set fits this stage's active capture allocation.
        let mut interfaces = Vec::with_capacity(source_ceiling);
        for interface in &plan.interfaces {
            interfaces.push(interface.clone());
        }
        let mut fits = true;
        for interface in &admission.interfaces {
            if interfaces
                .iter()
                .any(|current| current.index == interface.index)
            {
                continue;
            }
            if interfaces.len() == source_ceiling {
                fits = false;
                break;
            }
            interfaces.push(interface.clone());
        }
        if !interfaces.is_empty() && fits {
            plan.interfaces = interfaces;
        }
    }
    let descriptions = initial
        .batches
        .into_iter()
        .map(|offer| {
            (
                offer.index,
                Descriptor {
                    batch: BatchStorage::Owned(offer.batch),
                    host_deadline: offer.host_deadline,
                    route: None,
                },
            )
        })
        .collect();
    let streaming = Streaming {
        done: initial.done,
        next_ready: initial.next_ready,
        max_probe_bytes: admission.max_probe_bytes,
        max_descriptor_bytes: descriptor_bytes,
        max_source_name_bytes: admission.max_source_name_bytes,
    };
    let mut pipeline = Pipeline::assemble(
        executor,
        options,
        deadline,
        started,
        Output::Stream(feed),
        history,
        InitialState {
            plan,
            descriptions,
            streaming: Some(streaming),
        },
    )?;
    let result = pipeline.drive();
    pipeline.finish(result)
}

impl<P: PacketProviders, K: Clock> Pipeline<'_, P, K> {
    /// Refill is called between cooperative capture boundaries, never from a
    /// publication thread. One controller remains the scheduling authority.
    pub(super) fn refill(&mut self, draining: bool) -> Result<(), BoundaryError> {
        if draining
            || self.streaming.is_none()
            || self.pending.len().saturating_add(self.ready.len()) >= self.options.max_in_flight
            || self.executor.client.now() < self.next_send
        {
            return Ok(());
        }
        if self
            .streaming
            .as_ref()
            .and_then(|stream| stream.next_ready)
            .is_some_and(|ready| ready > self.executor.client.now())
        {
            return Ok(());
        }
        let maximum = self
            .streaming
            .as_ref()
            .expect("streaming checked")
            .max_probe_bytes;
        while self.retained.saturating_add(maximum) > self.options.max_prepared_bytes
            && self.retire_recent()
        {}
        if self.retained.saturating_add(maximum) > self.options.max_prepared_bytes {
            for probe in self.ready.values_mut().rev() {
                if self.retained.saturating_add(maximum) <= self.options.max_prepared_bytes {
                    break;
                }
                if let Some(preview) = probe.retained.take() {
                    drop(preview);
                    self.retained -= probe.memory;
                }
            }
        }
        let room = self
            .options
            .max_prepared_bytes
            .saturating_sub(self.retained);
        let capacity = self
            .options
            .max_in_flight
            .saturating_sub(self.pending.len().saturating_add(self.ready.len()))
            .min(room / maximum.max(1));
        if capacity == 0 {
            if self.pending.is_empty() {
                return Err(limit(
                    "prepared descriptions",
                    self.options.max_prepared_bytes,
                ));
            }
            return Ok(());
        }
        let Output::Stream(feed) = &mut self.output else {
            unreachable!("streaming output")
        };
        let poll = feed.poll(capacity, self.executor.client.now())?;
        if poll.batches.len() > capacity {
            return Err(limit("stream window", capacity));
        }
        let selected = poll.batches.len();
        let stream = self.streaming.as_mut().expect("streaming checked");
        stream.done = poll.done;
        stream.next_ready = poll.next_ready;
        for offer in poll.batches {
            if self.descriptions.contains_key(&offer.index) {
                return Err(limit("stream attempt identity", crate::scan::MAX_PROBES));
            }
            let probe = offer.batch.probe()?;
            let keep = self
                .retained
                .saturating_add(maximum.saturating_mul(selected.saturating_add(1)))
                <= self.options.max_prepared_bytes;
            let (route, mut admitted) =
                prepare::admit_one(&mut self.plan, probe, self.options.max_prepared_bytes, keep)?;
            let actual_description = 512usize
                .saturating_add(
                    probe
                        .scope
                        .as_ref()
                        .map_or(0, crate::target::ResolvedZone::retained_bytes),
                )
                .saturating_add(prepare::route_charge(&route));
            if admitted.memory > maximum
                || route.interface().name.len()
                    > self
                        .streaming
                        .as_ref()
                        .expect("streaming checked")
                        .max_source_name_bytes
                || actual_description
                    > self
                        .streaming
                        .as_ref()
                        .expect("streaming checked")
                        .max_descriptor_bytes
            {
                return Err(limit(
                    "changed prepared descriptions",
                    self.options.max_prepared_bytes,
                ));
            }
            if admitted.retained.is_some()
                && self
                    .retained
                    .saturating_add(admitted.memory)
                    .saturating_add(maximum)
                    > self.options.max_prepared_bytes
            {
                drop(admitted.retained.take());
            }
            if admitted.retained.is_some() {
                self.retained += admitted.memory;
            }
            if self.plan.interfaces.contains(route.interface()) {
                self.armed_ready.insert(offer.index);
            }
            if let Some(deadline) = offer.host_deadline {
                self.ready_deadlines.insert((deadline, offer.index));
            }
            self.descriptions.insert(
                offer.index,
                Descriptor {
                    batch: BatchStorage::Owned(offer.batch),
                    host_deadline: offer.host_deadline,
                    route: Some(Box::new(route)),
                },
            );
            self.ready.insert(offer.index, admitted);
        }
        self.rotate_if_needed()
    }
    pub(super) fn done(&self) -> bool {
        self.streaming.as_ref().is_none_or(|stream| stream.done)
    }
}
