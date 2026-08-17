// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Mutation preparation, accounting, and reflected-field resolution.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::budget::Deadline;
use crate::error::{Classification, Kind};
use crate::{
    Packet,
    build::Builder,
    decode::Dissector,
    field::{FieldKind, FieldValue},
    registry::Registry,
};

use super::super::MAX_TARGET_FIELDS;
use super::super::error::{Error, duration_limit};
use super::super::execution::case_seed;

use super::super::run::{Campaign, ResolvedField};
use super::decode::dissect_built;
use super::value::{bounded_value_size, index_from, mutation_value, shrink_values};

pub(in crate::fuzz) fn prepare(
    request: &super::super::request::Request,
    packet: Packet,
    registry: Arc<Registry>,
    deadline: &mut Deadline,
) -> Result<Campaign, Error> {
    deadline
        .start_accounting(Duration::ZERO)
        .map_err(duration_limit)?;
    let started = Instant::now();
    validate_base_shape(&packet, request.build.max_layers)?;
    packet_reflected_value_bytes(&packet, request.limits)?;
    let fields = resolve_fields(&packet, &request.targets)?;
    let compatible_mutations = request
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
    if compatible_mutations.is_empty() {
        return Err(Error::NoCompatibleTargets);
    }

    let builder = Builder::new(Arc::clone(&registry));
    let dissector = Dissector::new(registry);
    let campaign = prepare_cases(
        request,
        &packet,
        &fields,
        &compatible_mutations,
        &builder,
        &dissector,
        deadline,
    )?;
    deadline
        .account(started.elapsed())
        .map_err(duration_limit)?;
    Ok(campaign)
}

#[derive(Default)]
struct Counters {
    built_cases: u64,
    built_bytes: u64,
    retained_bytes: u64,
}

struct CaseInputs<'a> {
    request: &'a super::super::request::Request,
    packet: &'a Packet,
    fields: &'a [ResolvedField],
    compatible_mutations: &'a [(super::super::request::Strategy, usize)],
    builder: &'a Builder,
    dissector: &'a Dissector,
}

fn prepare_cases(
    request: &super::super::request::Request,
    packet: &Packet,
    fields: &[ResolvedField],
    compatible_mutations: &[(super::super::request::Strategy, usize)],
    builder: &Builder,
    dissector: &Dissector,
    deadline: &Deadline,
) -> Result<Campaign, Error> {
    let mut cases = Vec::with_capacity(request.cases);
    let mut counters = Counters::default();
    let inputs = CaseInputs {
        request,
        packet,
        fields,
        compatible_mutations,
        builder,
        dissector,
    };
    for offset in 0..request.cases {
        deadline.check().map_err(duration_limit)?;
        cases.push(prepare_case(&inputs, offset, &mut counters)?);
    }
    Ok(Campaign {
        cases,
        built_case_count: counters.built_cases,
        built_byte_count: counters.built_bytes,
        retained_byte_count: counters.retained_bytes,
    })
}

fn prepare_case(
    inputs: &CaseInputs<'_>,
    offset: usize,
    counters: &mut Counters,
) -> Result<super::super::result::Case, Error> {
    let request = inputs.request;
    let compatible_mutations = inputs.compatible_mutations;
    let total_byte_limit = request.limits.max_total_bytes as u64;
    let index = request
        .first_case
        .checked_add(offset as u64)
        .ok_or(Error::CaseIndexOverflow)?;
    let seed = case_seed(request.seed, index);
    let selection_index = index_from(index, compatible_mutations.len());
    let strategy_round = index / compatible_mutations.len() as u64;
    let (strategy, field_index) = compatible_mutations[selection_index];
    let field = &inputs.fields[field_index];
    let mut recipe = inputs.packet.clone();
    let original = recipe
        .layer(field.target.layer)
        .expect("resolved layer must remain present")
        .field(&field.target.field)
        .expect("resolved field must remain readable");
    let mutated_value = mutation_value(
        strategy,
        field,
        &original,
        seed,
        strategy_round,
        request.limits,
    );
    let mutation = super::super::result::Mutation {
        layer: field.target.layer,
        protocol: field.protocol.clone(),
        field: field.target.field.clone(),
        strategy,
        original,
        value: mutated_value.clone(),
    };
    let shrink_values = shrink_values(&mutated_value, request.limits.max_shrink_steps);
    let mutation_result = recipe
        .layer_mut(field.target.layer)
        .expect("resolved mutable layer must remain present")
        .set_field(&field.target.field, mutated_value);
    let retained_value_bytes =
        retained_case_value_bytes(&mutation, &shrink_values, &recipe, request.limits)?;
    charge_retained_bytes(
        &mut counters.retained_bytes,
        retained_value_bytes,
        total_byte_limit,
    )?;
    let mut case = new_case(index, seed, mutation, shrink_values, recipe);
    if let Err(source) = mutation_result {
        case.error = Some(mutation_failure(source));
        return Ok(case);
    }
    build_case(
        &mut case,
        request,
        inputs.builder,
        inputs.dissector,
        counters,
        total_byte_limit,
    )?;
    Ok(case)
}

fn new_case(
    index: u64,
    seed: u64,
    mutation: super::super::result::Mutation,
    shrink_values: Vec<FieldValue>,
    recipe: Packet,
) -> super::super::result::Case {
    super::super::result::Case {
        index,
        seed,
        mutation,
        shrink_values,
        recipe,
        built: None,
        decoded: None,
        outcome: super::super::result::CaseOutcome::Rejected,
        error: None,
        diagnostics: Vec::new(),
    }
}

fn mutation_failure(source: impl std::fmt::Display) -> super::super::result::CaseFailure {
    super::super::result::CaseFailure::new(
        format!("mutation was rejected: {source}"),
        Classification::new(
            "packet.fuzz_mutation",
            Kind::Packet,
            Some(
                "select a type/range accepted by the target field or retain the rejected case as fuzz evidence",
            ),
        ),
        Vec::new(),
    )
}

fn build_case(
    case: &mut super::super::result::Case,
    request: &super::super::request::Request,
    builder: &Builder,
    dissector: &Dissector,
    counters: &mut Counters,
    total_byte_limit: u64,
) -> Result<(), Error> {
    match builder.build(
        case.recipe.clone(),
        crate::build::Context::default(),
        request.build.clone(),
    ) {
        Ok(built) => {
            let next_built_bytes = counters
                .built_bytes
                .checked_add(built.bytes.len() as u64)
                .ok_or(byte_limit(u64::MAX, total_byte_limit))?;
            if next_built_bytes > total_byte_limit {
                return Err(byte_limit(next_built_bytes, total_byte_limit));
            }
            charge_retained_bytes(
                &mut counters.retained_bytes,
                built.bytes.len() as u64,
                total_byte_limit,
            )?;
            case.diagnostics.extend_from_slice(&built.diagnostics);
            case.decoded = dissect_built(dissector, &built, request.limits, &mut case.diagnostics);
            if let Some(decoded) = &case.decoded {
                let decoded_bytes = packet_reflected_value_bytes(&decoded.packet, request.limits)?;
                charge_retained_bytes(
                    &mut counters.retained_bytes,
                    decoded_bytes,
                    total_byte_limit,
                )?;
            }
            case.built = Some(built);
            case.outcome = super::super::result::CaseOutcome::Built;
            counters.built_cases += 1;
            counters.built_bytes = next_built_bytes;
        }
        Err(source) => {
            case.error = Some(super::super::result::CaseFailure::new(
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
    Ok(())
}

fn validate_base_shape(packet: &Packet, max_layers: usize) -> Result<(), Error> {
    if packet.len() > max_layers {
        return Err(Error::InvalidBasePacket {
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
            .ok_or_else(|| Error::InvalidBasePacket {
                message: "reflected field-count arithmetic overflowed".to_owned(),
            })?;
        if fields > MAX_TARGET_FIELDS {
            return Err(Error::InvalidBasePacket {
                message: format!(
                    "packet schema exposes {fields} fields, exceeding hard limit {MAX_TARGET_FIELDS}"
                ),
            });
        }
    }
    Ok(())
}

fn retained_case_value_bytes(
    mutation: &super::super::result::Mutation,
    shrink_values: &[FieldValue],
    recipe: &Packet,
    limits: super::super::request::Limits,
) -> Result<u64, Error> {
    let limit = limits.max_total_bytes as u64;
    let mut total = (mutation.protocol.len() as u64)
        .checked_add(mutation.field.len() as u64)
        .ok_or(byte_limit(u64::MAX, limit))?;
    for value in std::iter::once(&mutation.original)
        .chain(std::iter::once(&mutation.value))
        .chain(shrink_values)
    {
        let remaining = limits
            .max_total_bytes
            .saturating_sub(usize::try_from(total).unwrap_or(usize::MAX));
        let size = bounded_value_size(value, remaining, limits.max_list_items, 0)
            .ok_or(byte_limit(limit + 1, limit))?;
        total = total
            .checked_add(size as u64)
            .ok_or(byte_limit(u64::MAX, limit))?;
    }
    total
        .checked_add(packet_reflected_value_bytes(recipe, limits)?)
        .ok_or(byte_limit(u64::MAX, limit))
}

fn packet_reflected_value_bytes(
    packet: &Packet,
    limits: super::super::request::Limits,
) -> Result<u64, Error> {
    let mut total = 0_u64;
    let limit = limits.max_total_bytes as u64;
    for layer in packet.iter() {
        for field in layer.schema().fields {
            let Some(value) = layer.field(field.name) else {
                continue;
            };
            let remaining = limits
                .max_total_bytes
                .saturating_sub(usize::try_from(total).unwrap_or(usize::MAX));
            let size = bounded_value_size(&value, remaining, limits.max_list_items, 0)
                .ok_or(byte_limit(limit + 1, limit))?;
            total = total
                .checked_add(size as u64)
                .ok_or(byte_limit(u64::MAX, limit))?;
        }
    }
    Ok(total)
}

fn charge_retained_bytes(total: &mut u64, value: u64, limit: u64) -> Result<(), Error> {
    let next = total
        .checked_add(value)
        .ok_or(byte_limit(u64::MAX, limit))?;
    if next > limit {
        return Err(byte_limit(next, limit));
    }
    *total = next;
    Ok(())
}

fn byte_limit(actual: u64, limit: u64) -> Error {
    Error::ByteLimit { actual, limit }
}

fn resolve_fields(
    packet: &Packet,
    requested: &[super::super::request::Target],
) -> Result<Vec<ResolvedField>, Error> {
    if requested.is_empty() {
        let mut fields = Vec::new();
        for (layer_index, layer) in packet.iter().enumerate() {
            for field in layer.schema().fields {
                if layer.field(field.name).is_none() {
                    continue;
                }
                if fields.len() >= MAX_TARGET_FIELDS {
                    return Err(Error::InvalidBasePacket {
                        message: format!(
                            "packet exposes more than {MAX_TARGET_FIELDS} reflected fields"
                        ),
                    });
                }
                fields.push(ResolvedField {
                    target: super::super::request::Target {
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
            return Err(Error::NoCompatibleTargets);
        }
        return Ok(fields);
    }

    if requested.len() > MAX_TARGET_FIELDS {
        return Err(Error::InvalidBasePacket {
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
            .ok_or_else(|| Error::InvalidTarget {
                target: target.clone(),
                message: format!("layer index is outside packet length {}", packet.len()),
            })?;
        let schema = layer
            .schema()
            .fields
            .iter()
            .find(|field| field.name == target.field)
            .ok_or_else(|| Error::InvalidTarget {
                target: target.clone(),
                message: format!("layer {} has no such reflected field", layer.protocol_id()),
            })?;
        if layer.field(schema.name).is_none() {
            return Err(Error::InvalidTarget {
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

fn strategy_compatible(strategy: super::super::request::Strategy, field: &ResolvedField) -> bool {
    match strategy {
        super::super::request::Strategy::Boundary | super::super::request::Strategy::Random => true,
        super::super::request::Strategy::BitFlip => field.kind == FieldKind::Bytes,
        super::super::request::Strategy::Malformed => field.is_derived,
    }
}
