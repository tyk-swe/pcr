// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use super::{Batch, limit};
use crate::{
    BoundaryError, Client,
    materialize::PlannedPacket,
    policy::{Operation, WireBudget},
    probe::{ExchangeExecutor, PipelineOptions},
};
use packetcraftr_core::{build::Builder, field::FieldValue, packet::Packet};
use packetcraftr_netio::{neighbor, route, transmit};
use std::{collections::HashMap, net::IpAddr, time::Instant};
#[derive(Clone, Copy)]
pub(super) struct Cost {
    pub wire: usize,
    pub memory: usize,
}
pub(super) struct Plan {
    pub routes: HashMap<IpAddr, route::Plan>,
    pub costs: Vec<Cost>,
    pub interfaces: Vec<packetcraftr_netio::interface::Id>,
    pub base_bytes: usize,
}
pub(super) fn plan<R, N, I>(
    executor: &ExchangeExecutor<'_, R, N, I>,
    batches: &[Batch],
    options: PipelineOptions,
    deadline: Instant,
) -> Result<Plan, BoundaryError>
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
    let builder = Builder::new(client.registry.clone());
    let mut routes = HashMap::new();
    let mut interfaces = Vec::new();
    let mut costs = Vec::with_capacity(batches.len());
    let mut total = 0u64;
    let mut base_bytes = batches
        .len()
        .checked_mul(384)
        .ok_or_else(|| limit("prepared descriptions", options.max_prepared_bytes))?;
    if base_bytes > options.max_prepared_bytes {
        return Err(limit("prepared descriptions", options.max_prepared_bytes));
    }
    client
        .policy
        .authorize(Operation::Budgeted(WireBudget::new(
            batches.len() as u64,
            0,
        )))
        .map_err(BoundaryError::from_error)?;
    for batch in batches {
        super::check(client, deadline)?;
        let packet = batch.probe().packet();
        if !super::super::probe::sent_probe_matches(batch.probe(), &packet) {
            return Err(BoundaryError::from_error(super::super::profile::Error(
                "probe fields differ from its selected profile",
            )));
        }
        let route = match routes.get(&batch.probe().address) {
            Some(route) => route::Plan::clone(route),
            None => {
                let route = client
                    .plan_with_provider(
                        &packet,
                        Some(batch.probe().address),
                        &executor.options.send.plan,
                        &client.routes,
                        Some(deadline),
                    )
                    .map_err(BoundaryError::from_error)?;
                if !interfaces
                    .iter()
                    .any(|interface| interface == &route.decision.interface)
                {
                    interfaces.push(route.decision.interface.clone());
                    if interfaces.len() > packetcraftr_netio::capture::group::MAX_SOURCES {
                        return Err(limit(
                            "capture interfaces",
                            packetcraftr_netio::capture::group::MAX_SOURCES,
                        ));
                    }
                }
                base_bytes = base_bytes
                    .checked_add(2048 + route.decision.interface.name.len())
                    .ok_or_else(|| limit("prepared descriptions", options.max_prepared_bytes))?;
                if base_bytes > options.max_prepared_bytes {
                    return Err(limit("prepared descriptions", options.max_prepared_bytes));
                }
                routes.insert(batch.probe().address, route.clone());
                route
            }
        };
        let prepared = planned(
            client,
            batch,
            route,
            &builder,
            &executor.options.send,
            deadline,
        )?;
        let wire = prepared.preliminary_build.bytes.len();
        total = total
            .checked_add(wire as u64)
            .ok_or_else(|| limit("wire bytes", usize::MAX))?;
        client
            .policy
            .authorize(Operation::Budgeted(WireBudget::new(
                batches.len() as u64,
                total,
            )))
            .map_err(BoundaryError::from_error)?;
        let memory = charge(&prepared.packet, options.max_prepared_bytes)?
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(wire))
            .ok_or_else(|| limit("prepared descriptions", options.max_prepared_bytes))?;
        if base_bytes.saturating_add(memory) > options.max_prepared_bytes {
            return Err(limit("prepared descriptions", options.max_prepared_bytes));
        }
        costs.push(Cost { wire, memory });
    }
    if costs
        .iter()
        .any(|cost| cost.memory.saturating_add(base_bytes) > options.max_prepared_bytes)
    {
        return Err(limit("prepared descriptions", options.max_prepared_bytes));
    }
    Ok(Plan {
        routes,
        costs,
        interfaces,
        base_bytes,
    })
}
pub(super) fn planned<R, N, I>(
    client: &Client<R, N, I>,
    batch: &Batch,
    route: route::Plan,
    builder: &Builder,
    options: &crate::send::Options,
    deadline: Instant,
) -> Result<PlannedPacket, BoundaryError>
where
    R: route::Provider,
    N: neighbor::Resolver,
    I: transmit::Sender,
{
    let mut options = options.clone();
    options.destination = Some(batch.probe().address);
    client
        .plan_and_authorize(
            batch.probe().packet(),
            route,
            builder,
            &options,
            Some(deadline),
        )
        .map_err(BoundaryError::from_error)
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
