// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Mutation preparation, accounting, and reflected-field resolution.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::budget::Deadline;
use crate::error::{Classification, Kind};
use crate::{
    Packet,
    build::{BuildContext, Builder},
    decode::Dissector,
    field::{FieldKind, FieldValue},
    registry::Registry,
};

use super::super::MAX_TARGET_FIELDS;
use super::super::error::{FuzzError, duration_limit};
use super::super::execution::case_seed;
use super::super::request::{FuzzLimits, FuzzRequest, FuzzStrategy, FuzzTarget};
use super::super::result::{FuzzCase, FuzzCaseFailure, FuzzCaseOutcome, FuzzMutation};
use super::super::run::{Campaign, ResolvedField};
use super::decode::dissect_built;
use super::value::{bounded_value_size, index_from, mutation_value, shrink_values};

pub(in crate::fuzz) fn prepare(
    request: &FuzzRequest,
    packet: Packet,
    registry: Arc<Registry>,
    deadline: &mut Deadline,
) -> Result<Campaign, FuzzError> {
    deadline
        .start_accounting(Duration::ZERO)
        .map_err(duration_limit)?;
    let started = Instant::now();
    validate_base_shape(&packet, request.build.max_layers)?;
    packet_reflected_value_bytes(&packet, request.limits)?;
    let fields = resolve_fields(&packet, &request.targets)?;
    let pairs = request
        .strategies
        .iter()
        .copied()
        .flat_map(|strategy| {
            fields
                .iter()
                .enumerate()
                .filter(move |(_, field)| strategy_compatible(strategy, field))
                .map(move |(field_index, _)| (strategy, field_index))
        })
        .collect::<Vec<_>>();
    if pairs.is_empty() {
        return Err(FuzzError::NoCompatibleTargets);
    }

    let builder = Builder::new(Arc::clone(&registry));
    let dissector = Dissector::new(registry);
    let mut cases = Vec::with_capacity(request.cases);
    let mut built_case_count = 0_u64;
    let mut built_byte_count = 0_u64;
    let mut retained_bytes = 0_u64;
    for offset in 0..request.cases {
        deadline.check().map_err(duration_limit)?;
        let index = request
            .first_case
            .checked_add(offset as u64)
            .ok_or(FuzzError::CaseIndexOverflow)?;
        let seed = case_seed(request.seed, index);
        let pair_index = index_from(index, pairs.len());
        let round = index / pairs.len() as u64;
        let (strategy, field_index) = pairs[pair_index];
        let field = &fields[field_index];
        let mut recipe = packet.clone();
        let layer = recipe
            .layer(field.target.layer)
            .expect("resolved layer must remain present");
        let original = layer
            .field(&field.target.field)
            .expect("resolved field must remain readable");
        let value = mutation_value(strategy, field, &original, seed, round, request.limits);
        let mutation = FuzzMutation {
            layer: field.target.layer,
            protocol: field.protocol.clone(),
            field: field.target.field.clone(),
            strategy,
            original: original.clone(),
            value: value.clone(),
        };
        let shrink_values = shrink_values(&value, request.limits.max_shrink_steps);
        let set_result = recipe
            .layer_mut(field.target.layer)
            .expect("resolved mutable layer must remain present")
            .set_field(&field.target.field, value);
        let case_value_bytes =
            retained_case_value_bytes(&mutation, &shrink_values, &recipe, request.limits)?;
        charge_retained_bytes(
            &mut retained_bytes,
            case_value_bytes,
            request.limits.max_total_bytes as u64,
        )?;
        let mut case = FuzzCase {
            index,
            seed,
            mutation,
            shrink_values,
            recipe,
            built: None,
            decoded: None,
            outcome: FuzzCaseOutcome::Rejected,
            error: None,
            diagnostics: Vec::new(),
        };
        if let Err(source) = set_result {
            case.error = Some(FuzzCaseFailure::new(
                format!("mutation was rejected: {source}"),
                Classification::new(
                    "packet.fuzz_mutation",
                    Kind::Packet,
                    Some(
                        "select a type/range accepted by the target field or retain the rejected case as fuzz evidence",
                    ),
                ),
                Vec::new(),
            ));
            cases.push(case);
            continue;
        }

        match builder.build(
            case.recipe.clone(),
            BuildContext::default(),
            request.build.clone(),
        ) {
            Ok(built) => {
                let next_built_byte_count = built_byte_count
                    .checked_add(built.bytes.len() as u64)
                    .ok_or(FuzzError::ByteLimit {
                        actual: u64::MAX,
                        limit: request.limits.max_total_bytes as u64,
                    })?;
                if next_built_byte_count > request.limits.max_total_bytes as u64 {
                    return Err(FuzzError::ByteLimit {
                        actual: next_built_byte_count,
                        limit: request.limits.max_total_bytes as u64,
                    });
                }
                charge_retained_bytes(
                    &mut retained_bytes,
                    built.bytes.len() as u64,
                    request.limits.max_total_bytes as u64,
                )?;
                case.diagnostics.extend(built.diagnostics.clone());
                case.decoded =
                    dissect_built(&dissector, &built, request.limits, &mut case.diagnostics);
                if let Some(decoded) = &case.decoded {
                    let decoded_bytes =
                        packet_reflected_value_bytes(&decoded.packet, request.limits)?;
                    charge_retained_bytes(
                        &mut retained_bytes,
                        decoded_bytes,
                        request.limits.max_total_bytes as u64,
                    )?;
                }
                case.built = Some(built);
                case.outcome = FuzzCaseOutcome::Built;
                built_case_count += 1;
                built_byte_count = next_built_byte_count;
            }
            Err(source) => {
                case.error = Some(FuzzCaseFailure::new(
                    format!("mutated packet was rejected: {source}"),
                    Classification::new(
                        "packet.fuzz_build",
                        Kind::Packet,
                        Some(
                            "reproduce the case in permissive offline mode when malformed dependent fields are intentional",
                        ),
                    ),
                    Vec::new(),
                ));
            }
        }
        cases.push(case);
    }
    deadline
        .account(started.elapsed())
        .map_err(duration_limit)?;
    Ok(Campaign {
        cases,
        built_case_count,
        built_byte_count,
        retained_byte_count: retained_bytes,
    })
}

fn validate_base_shape(packet: &Packet, max_layers: usize) -> Result<(), FuzzError> {
    if packet.len() > max_layers {
        return Err(FuzzError::InvalidBasePacket {
            message: format!(
                "packet has {} layers, exceeding build.max_layers={max_layers}",
                packet.len()
            ),
        });
    }
    let mut fields = 0_usize;
    for layer in packet.iter() {
        fields = fields
            .checked_add(layer.schema().fields.len())
            .ok_or_else(|| FuzzError::InvalidBasePacket {
                message: "reflected field-count arithmetic overflowed".to_owned(),
            })?;
        if fields > MAX_TARGET_FIELDS {
            return Err(FuzzError::InvalidBasePacket {
                message: format!(
                    "packet schema exposes {fields} fields, exceeding hard limit {MAX_TARGET_FIELDS}"
                ),
            });
        }
    }
    Ok(())
}

fn retained_case_value_bytes(
    mutation: &FuzzMutation,
    shrink_values: &[FieldValue],
    recipe: &Packet,
    limits: FuzzLimits,
) -> Result<u64, FuzzError> {
    let mut total = (mutation.protocol.len() as u64)
        .checked_add(mutation.field.len() as u64)
        .ok_or(FuzzError::ByteLimit {
            actual: u64::MAX,
            limit: limits.max_total_bytes as u64,
        })?;
    for value in std::iter::once(&mutation.original)
        .chain(std::iter::once(&mutation.value))
        .chain(shrink_values)
    {
        let remaining = limits
            .max_total_bytes
            .saturating_sub(usize::try_from(total).unwrap_or(usize::MAX));
        let size = bounded_value_size(value, remaining, limits.max_list_items, 0).ok_or(
            FuzzError::ByteLimit {
                actual: limits.max_total_bytes as u64 + 1,
                limit: limits.max_total_bytes as u64,
            },
        )?;
        total = total.checked_add(size as u64).ok_or(FuzzError::ByteLimit {
            actual: u64::MAX,
            limit: limits.max_total_bytes as u64,
        })?;
    }
    total
        .checked_add(packet_reflected_value_bytes(recipe, limits)?)
        .ok_or(FuzzError::ByteLimit {
            actual: u64::MAX,
            limit: limits.max_total_bytes as u64,
        })
}

fn packet_reflected_value_bytes(packet: &Packet, limits: FuzzLimits) -> Result<u64, FuzzError> {
    let mut total = 0_u64;
    for layer in packet.iter() {
        for field in layer.schema().fields {
            let Some(value) = layer.field(field.name) else {
                continue;
            };
            let remaining = limits
                .max_total_bytes
                .saturating_sub(usize::try_from(total).unwrap_or(usize::MAX));
            let size = bounded_value_size(&value, remaining, limits.max_list_items, 0).ok_or(
                FuzzError::ByteLimit {
                    actual: limits.max_total_bytes as u64 + 1,
                    limit: limits.max_total_bytes as u64,
                },
            )?;
            total = total.checked_add(size as u64).ok_or(FuzzError::ByteLimit {
                actual: u64::MAX,
                limit: limits.max_total_bytes as u64,
            })?;
        }
    }
    Ok(total)
}

fn charge_retained_bytes(total: &mut u64, value: u64, limit: u64) -> Result<(), FuzzError> {
    let next = total.checked_add(value).ok_or(FuzzError::ByteLimit {
        actual: u64::MAX,
        limit,
    })?;
    if next > limit {
        return Err(FuzzError::ByteLimit {
            actual: next,
            limit,
        });
    }
    *total = next;
    Ok(())
}

fn resolve_fields(
    packet: &Packet,
    requested: &[FuzzTarget],
) -> Result<Vec<ResolvedField>, FuzzError> {
    if requested.is_empty() {
        let mut fields = Vec::new();
        for (layer_index, layer) in packet.iter().enumerate() {
            for field in layer.schema().fields {
                if layer.field(field.name).is_none() {
                    continue;
                }
                if fields.len() >= MAX_TARGET_FIELDS {
                    return Err(FuzzError::InvalidBasePacket {
                        message: format!(
                            "packet exposes more than {MAX_TARGET_FIELDS} reflected fields"
                        ),
                    });
                }
                fields.push(ResolvedField {
                    target: FuzzTarget {
                        layer: layer_index,
                        field: field.name.to_owned(),
                    },
                    protocol: layer.protocol_id().to_string(),
                    kind: field.kind,
                    is_derived: field.derived,
                });
            }
        }
        if fields.is_empty() {
            return Err(FuzzError::NoCompatibleTargets);
        }
        return Ok(fields);
    }

    if requested.len() > MAX_TARGET_FIELDS {
        return Err(FuzzError::InvalidBasePacket {
            message: format!(
                "request selects {} fields, exceeding hard limit {MAX_TARGET_FIELDS}",
                requested.len()
            ),
        });
    }
    let mut fields = Vec::with_capacity(requested.len());
    for target in requested {
        if fields
            .iter()
            .any(|field: &ResolvedField| field.target == *target)
        {
            continue;
        }
        let layer = packet
            .layer(target.layer)
            .ok_or_else(|| FuzzError::InvalidTarget {
                target: target.clone(),
                message: format!("layer index is outside packet length {}", packet.len()),
            })?;
        let schema = layer
            .schema()
            .fields
            .iter()
            .find(|field| field.name == target.field)
            .ok_or_else(|| FuzzError::InvalidTarget {
                target: target.clone(),
                message: format!("layer {} has no such reflected field", layer.protocol_id()),
            })?;
        if layer.field(schema.name).is_none() {
            return Err(FuzzError::InvalidTarget {
                target: target.clone(),
                message: "field is not reflectively readable".to_owned(),
            });
        }
        fields.push(ResolvedField {
            target: target.clone(),
            protocol: layer.protocol_id().to_string(),
            kind: schema.kind,
            is_derived: schema.derived,
        });
    }
    Ok(fields)
}

fn strategy_compatible(strategy: FuzzStrategy, field: &ResolvedField) -> bool {
    match strategy {
        FuzzStrategy::Boundary | FuzzStrategy::Random => true,
        FuzzStrategy::BitFlip => field.kind == FieldKind::Bytes,
        FuzzStrategy::Malformed => field.is_derived,
    }
}
