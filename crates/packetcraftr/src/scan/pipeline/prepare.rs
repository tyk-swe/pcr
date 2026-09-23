// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use super::{Batch, limit};
use crate::{
    BoundaryError,
    preparation::{AdmittedCost, AuthorizedRoute, Discovery},
    probe::{ExchangeExecutor, PipelineOptions},
};
use packetcraftr_core::{field::FieldValue, packet::Packet};
use packetcraftr_netio::{capture::group::MAX_SOURCES, interface, neighbor, route, transmit};
use std::{
    collections::{HashMap, hash_map::Entry},
    net::IpAddr,
    time::Instant,
};
/// What the pipeline keeps after every probe was admitted: the discovery
/// phase that rebuilds each probe at send time, one route per probe address,
/// each probe's admitted cost (consumed in send order) and prepared-description
/// memory charge, and the capture interfaces.
pub(super) struct Plan<'c, R, N, I> {
    pub discovery: Discovery<'c, R, N, I>,
    pub routes: HashMap<IpAddr, AuthorizedRoute>,
    pub costs: Vec<AdmittedCost>,
    pub memory: Vec<usize>,
    pub interfaces: Vec<interface::Id>,
    pub base_bytes: usize,
}
/// Admits every probe before any neighbor discovery, charging the prepared
/// descriptions the pipeline may hold at once against `max_prepared_bytes`.
pub(super) fn plan<'c, R, N, I>(
    executor: &'c ExchangeExecutor<'_, R, N, I>,
    batches: &[Batch],
    options: PipelineOptions,
    deadline: Instant,
) -> Result<Plan<'c, R, N, I>, BoundaryError>
where
    R: route::Provider,
    N: neighbor::Resolver,
    I: transmit::Sender,
{
    executor
        .options
        .validate()
        .map_err(BoundaryError::from_error)?;
    let client = executor.client;
    let mut routes = HashMap::new();
    let mut interfaces = Vec::new();
    let mut costs = Vec::with_capacity(batches.len());
    let mut memory = Vec::with_capacity(batches.len());
    let mut base_bytes = batches
        .len()
        .checked_mul(384)
        .ok_or_else(|| limit("prepared descriptions", options.max_prepared_bytes))?;
    if base_bytes > options.max_prepared_bytes {
        return Err(limit("prepared descriptions", options.max_prepared_bytes));
    }
    let mut admission = client
        .admission(&executor.options.send, batches.len() as u64, deadline)
        .map_err(BoundaryError::from_error)?;
    for batch in batches {
        super::check(client, deadline)?;
        let packet = batch.probe().packet();
        if !super::super::probe::sent_probe_matches(batch.probe(), &packet) {
            return Err(BoundaryError::from_error(super::super::profile::Error(
                "probe fields differ from its selected profile",
            )));
        }
        let route = match routes.entry(batch.probe().address) {
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
        memory.push(charge);
        costs.push(admitted.into_cost());
    }
    if memory
        .iter()
        .any(|charge| charge.saturating_add(base_bytes) > options.max_prepared_bytes)
    {
        return Err(limit("prepared descriptions", options.max_prepared_bytes));
    }
    Ok(Plan {
        discovery: admission.discover(),
        routes,
        costs,
        memory,
        interfaces,
        base_bytes,
    })
}
fn charge(packet: &Packet, maximum: usize) -> Result<usize, BoundaryError> {
    fn value(value: &FieldValue, maximum: usize) -> Result<usize, BoundaryError> {
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
    fn value_cost(v: &FieldValue, max: usize) -> Result<usize, BoundaryError> {
        value(v, max)
    }
    let mut bytes = 1024usize;
    for layer in packet.iter() {
        bytes = bytes.saturating_add(256);
        for field in layer.schema().fields {
            if let Some(field) = layer.field(field.name) {
                bytes = bytes.saturating_add(value(&field, maximum)?);
            }
        }
        if bytes > maximum {
            return Err(limit("prepared descriptions", maximum));
        }
    }
    Ok(bytes)
}
