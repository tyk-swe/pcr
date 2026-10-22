// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use super::{Planned, limit};
use crate::{
    clock::Clock,
    engine::preparation::{AdmittedCost, Admitting, AuthorizedRoute, RetainedAdmission},
    exchange::WorkflowExecutor,
    providers::PacketProviders,
    scan::executor::PipelineOptions,
};
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::{budget::Deadline, field, packet::Packet};
use packetcraftr_netio::{capture::MAX_SOURCES, interface};
use std::{
    collections::{HashMap, hash_map::Entry},
    net::IpAddr,
    time::Instant,
};
pub(super) struct Plan<'c, P, K> {
    pub admission: Admitting<'c, P, K>,
    pub routes: HashMap<(IpAddr, Option<interface::Id>), AuthorizedRoute>,
    pub probes: Vec<AdmittedProbe>,
    pub interfaces: Vec<interface::Id>,
    pub interfaces_bytes: usize,
    pub base_bytes: usize,
}
pub(super) struct AdmittedProbe {
    pub cost: AdmittedCost,
    pub memory: usize,
    pub retained: Option<RetainedAdmission>,
}
/// Admits every probe before any neighbor discovery, charging the prepared
/// descriptions the pipeline may hold at once against `max_prepared_bytes`.
pub(super) fn plan<'c, P: PacketProviders, K: Clock>(
    executor: &'c WorkflowExecutor<'_, P, K>,
    planned: &[Planned<'_>],
    options: &PipelineOptions,
    deadline: Instant,
    preparation: &'c Deadline,
    retain: bool,
) -> Result<Plan<'c, P, K>, BoundaryError> {
    plan_with_limit(
        executor,
        planned,
        options,
        deadline,
        preparation,
        retain,
        planned.len(),
    )
}

pub(super) fn plan_with_limit<'c, P: PacketProviders, K: Clock>(
    executor: &'c WorkflowExecutor<'_, P, K>,
    planned: &[Planned<'_>],
    options: &PipelineOptions,
    deadline: Instant,
    preparation: &'c Deadline,
    retain: bool,
    packet_limit: usize,
) -> Result<Plan<'c, P, K>, BoundaryError> {
    executor
        .collection
        .validate()
        .map_err(BoundaryError::from_error)?;
    let client = executor.client;
    let mut routes = HashMap::new();
    // This stack contains only resident previews, never completed/history
    // entries. Removing optional cache ownership takes constant work per entry.
    let mut previews = Vec::new();
    let mut max_probe_bytes = 0usize;
    let indexed = planned.len().min(options.max_in_flight.saturating_mul(2));
    let mut index_bytes = super::correlation::index_charge(indexed, 0);
    let source_capacity = planned.len().min(MAX_SOURCES);
    // Reserve source-vector capacity before allocation. Strings are charged
    // individually before cloning; this table is separate from route owners.
    let mut interfaces_bytes = 256usize
        .saturating_add(source_capacity.saturating_mul(std::mem::size_of::<interface::Id>()));
    let mut base_bytes = planned.iter().fold(
        super::expiry::charge(planned.len().min(options.max_in_flight)),
        |bytes, planned| {
            let scope_bytes = planned
                .probe
                .scope
                .as_ref()
                .map_or(0, crate::target::ResolvedZone::retained_bytes);
            bytes.saturating_add(384).saturating_add(scope_bytes)
        },
    );
    base_bytes = base_bytes
        .saturating_add(index_bytes)
        .saturating_add(interfaces_bytes);
    if base_bytes > options.max_prepared_bytes {
        return Err(limit("prepared descriptions", options.max_prepared_bytes));
    }
    let mut interfaces = Vec::with_capacity(source_capacity);
    let mut admitted_probes = Vec::with_capacity(planned.len());
    let mut operation = executor.operation.clone();
    operation
        .spent
        .checked_add_assign(&options.preceding)
        .map_err(|error| {
            BoundaryError::from_error(crate::scan::error::probe_error(
                0,
                crate::engine::execution::Failure::StatsOverflow(error),
            ))
        })?;
    let mut admission = client
        .admitting_in(&executor.send, packet_limit as u64, preparation, &operation)
        .map_err(BoundaryError::from_error)?;
    for (index, &Planned { probe, .. }) in planned.iter().enumerate() {
        super::check(client, deadline, preparation)?;
        let packet = probe.packet();
        if !crate::scan::plan::packet::sent_probe_matches(probe, &packet) {
            return Err(BoundaryError::from_error(
                crate::scan::profile::Error::Invalid(
                    "probe fields differ from its selected profile",
                ),
            ));
        }
        // A scoped map key owns a separate name from both the declared scope
        // and AuthorizedRoute. Reserve its clone before lookup/insertion.
        let key_bytes = probe
            .scope
            .as_ref()
            .map_or(0, |scope| scope.interface.name.len());
        if !make_room(
            &mut admitted_probes,
            &mut previews,
            &mut base_bytes,
            key_bytes.saturating_add(max_probe_bytes),
            options.max_prepared_bytes,
        ) {
            return Err(limit("prepared descriptions", options.max_prepared_bytes));
        }
        base_bytes += key_bytes;
        let scope = probe.scope.as_ref().map(|scope| scope.interface.clone());
        let route = match routes.entry((probe.address, scope)) {
            Entry::Occupied(entry) => {
                // HashMap::entry has already dropped the unused lookup key.
                base_bytes -= key_bytes;
                entry.into_mut()
            }
            Entry::Vacant(entry) => {
                let route = admission
                    .route_on(&packet, entry.key().0, entry.key().1.as_ref())
                    .map_err(BoundaryError::from_error)?;
                let new_source = !interfaces.contains(route.interface());
                if new_source && interfaces.len() == MAX_SOURCES {
                    return Err(limit("capture interfaces", MAX_SOURCES));
                }
                let source_name_bytes = if new_source {
                    route.interface().name.len()
                } else {
                    0
                };
                let next_index_bytes = super::correlation::index_charge(
                    indexed,
                    interfaces.len() + usize::from(new_source),
                );
                let additional = route_charge(&route)
                    .checked_add(source_name_bytes)
                    .and_then(|bytes| {
                        bytes.checked_add(next_index_bytes.saturating_sub(index_bytes))
                    })
                    .ok_or_else(|| limit("prepared descriptions", options.max_prepared_bytes))?;
                if !make_room(
                    &mut admitted_probes,
                    &mut previews,
                    &mut base_bytes,
                    additional.saturating_add(max_probe_bytes),
                    options.max_prepared_bytes,
                ) {
                    return Err(limit("prepared descriptions", options.max_prepared_bytes));
                }
                base_bytes += additional;
                index_bytes = next_index_bytes;
                if new_source {
                    interfaces.push(route.interface().clone());
                    interfaces_bytes += source_name_bytes;
                }
                entry.insert(route)
            }
        };
        let admitted = if retain && index < options.max_in_flight {
            admission.admit_retained_on(packet, route)
        } else {
            admission.admit_on(packet, route)
        }
        .map_err(BoundaryError::from_error)?;
        let charge = charge(admitted.packet(), options.max_prepared_bytes)?
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(admitted.wire_len()))
            .and_then(|bytes| bytes.checked_add(admitted.retained_route_name_bytes()))
            .and_then(|bytes| bytes.checked_add(route.scoped_name_bytes()))
            .ok_or_else(|| limit("prepared descriptions", options.max_prepared_bytes))?;
        max_probe_bytes = max_probe_bytes.max(charge);
        // Planning has no live probes. Reserve one runtime preparation overlap
        // before allocating/retaining the optional boxed preview. Later route,
        // source-index, or maximum-probe growth may evict these previews again.
        if !make_room(
            &mut admitted_probes,
            &mut previews,
            &mut base_bytes,
            max_probe_bytes,
            options.max_prepared_bytes,
        ) {
            return Err(limit("prepared descriptions", options.max_prepared_bytes));
        }
        let keep = retain
            && index < options.max_in_flight
            && base_bytes
                .saturating_add(charge)
                .saturating_add(max_probe_bytes)
                <= options.max_prepared_bytes;
        let (cost, retained) = if keep {
            admitted.into_parts()
        } else {
            (admitted.into_cost(), None)
        };
        if retained.is_some() {
            base_bytes += charge;
            previews.push(index);
        }
        admitted_probes.push(AdmittedProbe {
            cost,
            memory: charge,
            retained,
        });
    }
    if !make_room(
        &mut admitted_probes,
        &mut previews,
        &mut base_bytes,
        max_probe_bytes,
        options.max_prepared_bytes,
    ) {
        return Err(limit("prepared descriptions", options.max_prepared_bytes));
    }
    Ok(Plan {
        admission,
        routes,
        probes: admitted_probes,
        interfaces,
        interfaces_bytes,
        base_bytes,
    })
}

/// One bounded refill under the original stage admission and its cumulative budget.
pub(super) fn admit_one<P: PacketProviders, K: Clock>(
    plan: &mut Plan<'_, P, K>,
    probe: &crate::scan::Probe,
    maximum: usize,
    retain: bool,
) -> Result<(AuthorizedRoute, AdmittedProbe), BoundaryError> {
    let packet = probe.packet();
    if !crate::scan::plan::packet::sent_probe_matches(probe, &packet) {
        return Err(BoundaryError::from_error(
            crate::scan::profile::Error::Invalid("probe fields differ from its selected profile"),
        ));
    }
    let route = plan
        .admission
        .route_on(
            &packet,
            probe.address,
            probe.scope.as_ref().map(|scope| &scope.interface),
        )
        .map_err(BoundaryError::from_error)?;
    let admitted = if retain {
        plan.admission.admit_retained_on(packet, &route)
    } else {
        plan.admission.admit_on(packet, &route)
    }
    .map_err(BoundaryError::from_error)?;
    let memory = charge(admitted.packet(), maximum)?
        .checked_mul(3)
        .and_then(|bytes| bytes.checked_add(admitted.wire_len()))
        .and_then(|bytes| bytes.checked_add(admitted.retained_route_name_bytes()))
        .and_then(|bytes| bytes.checked_add(route.scoped_name_bytes()))
        .ok_or_else(|| limit("prepared descriptions", maximum))?;
    let (cost, retained) = admitted.into_parts();
    Ok((
        route,
        AdmittedProbe {
            cost,
            memory,
            retained,
        },
    ))
}

/// Route object metadata and every owned interface-name buffer. A map key and
/// the source table are separate owners and are charged by their containers.
pub(super) fn route_charge(route: &AuthorizedRoute) -> usize {
    2048usize.saturating_add(route.retained_name_bytes())
}

fn make_room(
    probes: &mut [AdmittedProbe],
    previews: &mut Vec<usize>,
    base: &mut usize,
    additional: usize,
    maximum: usize,
) -> bool {
    while base.saturating_add(additional) > maximum {
        let Some(index) = previews.pop() else {
            return false;
        };
        let preview = probes[index].retained.take();
        debug_assert!(preview.is_some(), "only resident previews are indexed");
        // Release the actual retained packet/builds before returning its charge.
        drop(preview);
        *base -= probes[index].memory;
    }
    true
}
fn charge(packet: &Packet, maximum: usize) -> Result<usize, BoundaryError> {
    fn value_cost(value: &field::Value, maximum: usize) -> Result<usize, BoundaryError> {
        let mut bytes = 64usize;
        match value {
            field::Value::Text(text) => bytes = bytes.saturating_add(text.len().saturating_mul(32)),
            field::Value::Bytes(data) => bytes = bytes.saturating_add(data.len().saturating_mul(3)),
            field::Value::List(values) => {
                for child in values {
                    bytes = bytes.saturating_add(value_cost(child, maximum)?);
                }
            }
            field::Value::Object(values) => {
                for (key, child) in values {
                    bytes = bytes
                        .saturating_add(256 + key.len())
                        .saturating_add(value_cost(child, maximum)?);
                }
            }
            _ => {}
        }
        if bytes > maximum {
            Err(limit("prepared descriptions", maximum))
        } else {
            Ok(bytes)
        }
    }
    let mut bytes = 1024usize;
    for layer in packet.iter() {
        bytes = bytes.saturating_add(256);
        for field in layer.schema().fields {
            if let Some(field) = layer.field(field.name) {
                bytes = bytes.saturating_add(value_cost(&field, maximum)?);
            }
        }
        if bytes > maximum {
            return Err(limit("prepared descriptions", maximum));
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
