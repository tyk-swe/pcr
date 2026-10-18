// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
//! Preflight admission and bounded adaptive runtime estimates.

use super::{
    AdaptiveAdmission, CaptureSession, Planned, correlation, expiry, limit, max_wait_secs, prepare,
    until, validate_options,
};
use crate::{
    clock::Clock,
    execution::ExchangeExecutor,
    probe::Batch,
    providers::{CaptureProviders, PacketProviders},
    scan::{Probe, executor::PipelineOptions},
};
use packetcraftr_core::error::BoundaryError;
use packetcraftr_netio::{capture, interface};

/// Admits `batches` as [`super::run`] would and keeps nothing, so a stage over its
/// preparation limit fails before anything is sent.
pub(in crate::scan::executor) fn admit<P: PacketProviders, K: Clock>(
    executor: &ExchangeExecutor<'_, P, K>,
    batches: &[Batch<Probe>],
    options: &PipelineOptions,
) -> Result<(), BoundaryError> {
    validate_options(batches, options)?;
    let deadline = executor
        .client
        .now()
        .checked_add(options.max_duration)
        .ok_or_else(|| limit("duration", max_wait_secs()))?;
    let planned = batches
        .iter()
        .map(Planned::new)
        .collect::<Result<Vec<_>, _>>()?;
    let preparation = until(executor.client, deadline, &options.control);
    prepare::plan(executor, &planned, options, deadline, &preparation, false).map(drop)
}

impl AdaptiveAdmission {
    pub(in crate::scan) fn new(effective_wave: usize) -> Self {
        Self {
            interfaces: Vec::new(),
            window: effective_wave,
            many_interfaces: false,
            max_description_bytes: 0,
            max_route_bytes: 0,
            max_map_route_bytes: 0,
            source_metadata_bytes: 0,
            max_source_name_bytes: 0,
            max_probe_bytes: 0,
            summary_bytes: 0,
        }
    }

    pub(in crate::scan) fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(
                self.interfaces
                    .capacity()
                    .saturating_mul(std::mem::size_of::<interface::Id>()),
            )
            .saturating_add(
                self.interfaces
                    .iter()
                    .map(|interface| interface.name.capacity())
                    .sum::<usize>(),
            )
    }

    pub(in crate::scan) fn reserve_summaries(&mut self, bytes: usize) {
        self.summary_bytes = bytes;
    }

    pub(in crate::scan) fn check(
        &self,
        wave_len: usize,
        host_count: usize,
        options: &PipelineOptions,
    ) -> Result<(), BoundaryError> {
        if self.window == 0 {
            return Ok(());
        }
        let window =
            wave_len
                .min(options.max_in_flight)
                .min(self.window)
                .min(if self.many_interfaces {
                    capture::MAX_SOURCES
                } else {
                    usize::MAX
                });
        let sources = window.min(capture::MAX_SOURCES);
        let descriptor = self
            .max_description_bytes
            .saturating_add(self.max_route_bytes)
            .saturating_add(512);
        let source_names = source_charge(
            sources,
            self.max_source_name_bytes,
            self.source_metadata_bytes,
        );
        let bound = correlation::index_charge(window.saturating_mul(2), sources)
            .saturating_add(expiry::charge(window))
            .saturating_add(window.saturating_mul(2).saturating_mul(descriptor))
            .saturating_add(
                window
                    .min(host_count)
                    .saturating_mul(self.max_map_route_bytes),
            )
            .saturating_add(source_names)
            .saturating_add(self.max_probe_bytes)
            .saturating_add(self.summary_bytes);
        if bound > options.max_prepared_bytes {
            return Err(limit("prepared descriptions", options.max_prepared_bytes));
        }
        Ok(())
    }
}

pub(super) fn source_charge(sources: usize, name_bytes: usize, metadata: usize) -> usize {
    // A closed epoch retains four names per source while the next interface
    // list, group request and partitioned requests are constructed. New native
    // sessions are armed only after assigning/dropping the old group.
    sources.saturating_mul(name_bytes.saturating_mul(7).saturating_add(metadata))
}

fn source_metadata<P: CaptureProviders>() -> usize {
    // Group::new allocates the next Owned<C> array before assignment drops
    // the old group. Include inline custom sessions and field/alignment slack,
    // even though the new session slots are not initialized until arm().
    let alignment =
        std::mem::align_of::<CaptureSession<P>>().max(std::mem::align_of::<capture::Source>());
    let owned = std::mem::size_of::<CaptureSession<P>>()
        .saturating_add(std::mem::size_of::<capture::Source>())
        .saturating_add(alignment.saturating_mul(2))
        .saturating_add(16);
    owned
        .saturating_add(std::mem::size_of::<capture::Request>())
        .saturating_mul(2)
        .saturating_add(std::mem::size_of::<capture::Metadata>())
        .saturating_add(std::mem::size_of::<interface::Id>().saturating_mul(3))
        .saturating_add(512)
}

pub(in crate::scan::executor) fn admit_adaptive<P: PacketProviders, K: Clock>(
    executor: &ExchangeExecutor<'_, P, K>,
    batches: &[Batch<Probe>],
    options: &PipelineOptions,
    summary: &mut AdaptiveAdmission,
) -> Result<(), BoundaryError> {
    summary.source_metadata_bytes = source_metadata::<P>();
    validate_options(batches, options)?;
    let deadline = executor
        .client
        .now()
        .checked_add(options.max_duration)
        .ok_or_else(|| limit("duration", max_wait_secs()))?;
    let planned = batches
        .iter()
        .map(Planned::new)
        .collect::<Result<Vec<_>, _>>()?;
    for planned in &planned {
        let scope_bytes = planned
            .probe
            .scope
            .as_ref()
            .map_or(0, crate::target::ResolvedZone::retained_bytes);
        summary.max_description_bytes = summary
            .max_description_bytes
            .max(384usize.saturating_add(scope_bytes));
    }
    let preparation = until(executor.client, deadline, &options.control);
    let plan = prepare::plan(executor, &planned, options, deadline, &preparation, false)?;
    let previous_summary_bytes = summary.retained_bytes();
    for ((_, scope), route) in &plan.routes {
        summary.max_route_bytes = summary.max_route_bytes.max(prepare::route_charge(route));
        summary.max_map_route_bytes = summary.max_map_route_bytes.max(
            prepare::route_charge(route)
                .saturating_add(scope.as_ref().map_or(0, |scope| scope.name.capacity())),
        );
        summary.max_source_name_bytes = summary
            .max_source_name_bytes
            .max(route.interface().name.len());
    }
    for probe in &plan.probes {
        summary.max_probe_bytes = summary.max_probe_bytes.max(probe.memory);
    }
    if !summary.many_interfaces {
        for interface in &plan.interfaces {
            if !summary.interfaces.contains(interface) {
                if summary.interfaces.len() == summary.window.min(capture::MAX_SOURCES) {
                    // More sources than the active allocation: a scalar sentinel
                    // replaces historical names instead of accumulating a cache.
                    summary.interfaces.clear();
                    summary.many_interfaces = true;
                    break;
                }
                // The caller already reserved the old summary. Charge each
                // additional name and the fixed table before copying it while
                // this temporary admission plan is still resident.
                let capacity_bytes = if summary.interfaces.capacity() == 0 {
                    summary
                        .window
                        .min(capture::MAX_SOURCES)
                        .saturating_mul(std::mem::size_of::<interface::Id>())
                } else {
                    0
                };
                let growth = summary
                    .retained_bytes()
                    .saturating_sub(previous_summary_bytes)
                    .saturating_add(capacity_bytes)
                    .saturating_add(interface.name.len());
                if plan
                    .base_bytes
                    .saturating_add(summary.max_probe_bytes)
                    .saturating_add(growth)
                    > options.max_prepared_bytes
                {
                    return Err(limit("prepared summaries", options.max_prepared_bytes));
                }
                if summary.interfaces.capacity() == 0 {
                    summary
                        .interfaces
                        .reserve_exact(summary.window.min(capture::MAX_SOURCES));
                }
                summary.interfaces.push(interface.clone());
            }
        }
    }
    drop(plan);
    Ok(())
}
