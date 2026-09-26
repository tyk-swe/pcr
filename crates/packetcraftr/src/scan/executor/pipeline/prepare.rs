// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use super::{Planned, limit};
use crate::{
    Providers,
    clock::Clock,
    execution::ExchangeExecutor,
    preparation::{AdmittedCost, AuthorizedRoute, Discovery},
    scan::executor::PipelineOptions,
};
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::{budget::Deadline, field::FieldValue, packet::Packet};
use packetcraftr_netio::{capture::MAX_SOURCES, interface};
use std::{
    collections::{HashMap, hash_map::Entry},
    net::IpAddr,
    time::Instant,
};
/// What the pipeline keeps after every probe was admitted: the discovery
/// phase that rebuilds each probe at send time, one route per probe address,
/// each probe's [`AdmittedProbe`] in send order, and the capture interfaces.
pub(super) struct Plan<'c, P, K> {
    pub discovery: Discovery<'c, P, K>,
    pub routes: HashMap<IpAddr, AuthorizedRoute>,
    pub probes: Vec<AdmittedProbe>,
    pub interfaces: Vec<interface::Id>,
    pub base_bytes: usize,
}
/// One admitted probe: the wire cost its send-time rebuild must match, and
/// the prepared-description memory it holds while in flight.
pub(super) struct AdmittedProbe {
    pub cost: AdmittedCost,
    pub memory: usize,
}
/// Admits every probe before any neighbor discovery, charging the prepared
/// descriptions the pipeline may hold at once against `max_prepared_bytes`.
/// Preparation runs under `preparation`, the provider view of `deadline`.
pub(super) fn plan<'c, P: Providers, K: Clock>(
    executor: &'c ExchangeExecutor<'_, P, K>,
    planned: &[Planned<'_>],
    options: PipelineOptions,
    deadline: Instant,
    preparation: &'c Deadline,
) -> Result<Plan<'c, P, K>, BoundaryError> {
    executor
        .collection
        .validate()
        .map_err(BoundaryError::from_error)?;
    let client = executor.client;
    let mut routes = HashMap::new();
    let mut interfaces = Vec::new();
    let mut admitted_probes = Vec::with_capacity(planned.len());
    let mut base_bytes = planned
        .len()
        .checked_mul(384)
        .ok_or_else(|| limit("prepared descriptions", options.max_prepared_bytes))?;
    if base_bytes > options.max_prepared_bytes {
        return Err(limit("prepared descriptions", options.max_prepared_bytes));
    }
    let mut admission = client
        .admitting(&executor.send, planned.len() as u64, preparation)
        .map_err(BoundaryError::from_error)?;
    for &Planned { probe, .. } in planned {
        super::check(client, deadline)?;
        let packet = probe.packet();
        if !crate::scan::plan::packet::sent_probe_matches(probe, &packet) {
            return Err(BoundaryError::from_error(crate::scan::profile::Error(
                "probe fields differ from its selected profile",
            )));
        }
        let route = match routes.entry(probe.address) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let route = admission
                    .route(&packet, *entry.key())
                    .map_err(BoundaryError::from_error)?;
                if !interfaces.contains(route.interface()) {
                    interfaces.push(route.interface().clone());
                    if interfaces.len() > MAX_SOURCES {
                        return Err(limit("capture interfaces", MAX_SOURCES));
                    }
                }
                base_bytes = base_bytes
                    .checked_add(2048 + route.interface().name.len())
                    .ok_or_else(|| limit("prepared descriptions", options.max_prepared_bytes))?;
                if base_bytes > options.max_prepared_bytes {
                    return Err(limit("prepared descriptions", options.max_prepared_bytes));
                }
                entry.insert(route)
            }
        };
        let admitted = admission
            .admit_on(packet, route)
            .map_err(BoundaryError::from_error)?;
        let charge = charge(admitted.packet(), options.max_prepared_bytes)?
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(admitted.wire_len()))
            .ok_or_else(|| limit("prepared descriptions", options.max_prepared_bytes))?;
        if base_bytes.saturating_add(charge) > options.max_prepared_bytes {
            return Err(limit("prepared descriptions", options.max_prepared_bytes));
        }
        admitted_probes.push(AdmittedProbe {
            cost: admitted.into_cost(),
            memory: charge,
        });
    }
    if admitted_probes
        .iter()
        .any(|probe| probe.memory.saturating_add(base_bytes) > options.max_prepared_bytes)
    {
        return Err(limit("prepared descriptions", options.max_prepared_bytes));
    }
    Ok(Plan {
        discovery: admission.discover(),
        routes,
        probes: admitted_probes,
        interfaces,
        base_bytes,
    })
}
fn charge(packet: &Packet, maximum: usize) -> Result<usize, BoundaryError> {
    fn value_cost(value: &FieldValue, maximum: usize) -> Result<usize, BoundaryError> {
        let mut bytes = 64usize;
        match value {
            FieldValue::Text(text) => bytes = bytes.saturating_add(text.len().saturating_mul(32)),
            FieldValue::Bytes(data) => bytes = bytes.saturating_add(data.len().saturating_mul(3)),
            FieldValue::List(values) => {
                for child in values {
                    bytes = bytes.saturating_add(value_cost(child, maximum)?);
                }
            }
            FieldValue::Object(values) => {
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
