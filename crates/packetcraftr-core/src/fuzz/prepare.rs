// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::budget::Deadline;
use crate::error::{Classification, Kind};
use crate::{
    build::Builder,
    decode::Dissector,
    field::{FieldKind, FieldValue, Path},
    packet::Packet,
    registry::Registry,
};

use super::decode::dissect_built;
use super::error::{BaseFault, Error, TargetFault};
use super::mutation::{ValueLimit, bounded_value_size, index_from, mutation_value, shrink_values};
use super::report::{Case, CaseFailure, CaseOutcome, Mutation, Stats};
use super::request::{Limits, Request, Strategy, Target};
use super::rng::case_seed;
use super::roundtrip;
use super::{MAX_TARGET_FIELDS, MAX_VALUE_NESTING};

#[derive(Clone)]
pub(super) struct ResolvedField {
    pub(super) target: Target,
    pub(super) path: Path,
    pub(super) protocol: String,
    pub(super) kind: FieldKind,
    pub(super) is_derived: bool,
}

pub(super) fn prepare_with_events<F>(
    request: &Request,
    packet: Packet,
    registry: Arc<Registry>,
    deadline: &mut Deadline,
    emit: &mut F,
) -> Result<Stats, Error>
where
    F: FnMut(Case, &Deadline) -> Result<(), Error>,
{
    deadline.check_cancelled()?;
    deadline
        .start_accounting(Duration::ZERO)
        .map_err(Error::from)?;
    let started = Instant::now();
    validate_base_shape(&packet, request.build.limits.max_layers)?;
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
    let inputs = CaseInputs {
        request,
        packet: &packet,
        fields: &fields,
        compatible_mutations: &compatible_mutations,
        builder: &builder,
        dissector: &dissector,
    };
    let counters = prepare_cases(&inputs, deadline, emit)?;
    let elapsed = started.elapsed();
    deadline.check_cancelled()?;
    deadline.account(elapsed).map_err(Error::from)?;
    Ok(Stats {
        cases_generated: u64::try_from(request.cases).unwrap_or(u64::MAX),
        cases_built: counters.built_cases,
        bytes: counters.built_bytes,
        elapsed,
    })
}

#[derive(Default)]
struct Counters {
    built_cases: u64,
    built_bytes: u64,
    retained_bytes: u64,
}

struct CaseInputs<'a> {
    request: &'a Request,
    packet: &'a Packet,
    fields: &'a [ResolvedField],
    compatible_mutations: &'a [(Strategy, usize)],
    builder: &'a Builder,
    dissector: &'a Dissector,
}

fn prepare_cases<F>(
    inputs: &CaseInputs<'_>,
    deadline: &Deadline,
    emit: &mut F,
) -> Result<Counters, Error>
where
    F: FnMut(Case, &Deadline) -> Result<(), Error>,
{
    let mut counters = Counters::default();
    for offset in 0..inputs.request.cases {
        deadline.enforce()?;
        let case = prepare_case(inputs, offset, &mut counters, deadline)?;
        emit(case, deadline)?;
    }
    Ok(counters)
}

fn prepare_case(
    inputs: &CaseInputs<'_>,
    offset: usize,
    counters: &mut Counters,
    deadline: &Deadline,
) -> Result<Case, Error> {
    let request = inputs.request;
    let compatible_mutations = inputs.compatible_mutations;
    let total_byte_limit = total_byte_limit(request.limits);
    let index = request
        .first_case
        .checked_add(offset as u64)
        .ok_or(Error::CaseIndexOverflow)?;
    let seed = case_seed(request.seed, index);
    let selection_index = index_from(index, compatible_mutations.len());
    // `prepare` returns before preparing cases when `compatible_mutations` is empty
    let strategy_round = index / compatible_mutations.len() as u64;
    let (strategy, field_index) = compatible_mutations[selection_index];
    // every `compatible_mutations` entry stores an index into `inputs.fields`
    let field = &inputs.fields[field_index];
    let mut recipe = inputs.packet.clone();
    let Some(layer) = recipe.layer_mut(field.target.layer) else {
        return Err(unresolved_target(
            field,
            TargetFault::LayerOutOfRange {
                layers: inputs.packet.len(),
            },
        ));
    };
    let Some(original) = layer.field_path(&field.path) else {
        return Err(unresolved_target(field, TargetFault::Unreadable));
    };
    let mutated_value = mutation_value(
        strategy,
        field,
        &*layer,
        &original,
        seed,
        strategy_round,
        request.limits,
    );
    let mutation = Mutation {
        layer: field.target.layer,
        protocol: field.protocol.clone(),
        field: field.target.field.clone(),
        strategy,
        original,
        value: mutated_value.clone(),
    };
    let shrink_values = shrink_values(&mutated_value, request.limits.max_shrink_steps);
    let mutation_result = layer.set_field_path(&field.path, mutated_value);
    let retained_value_bytes =
        retained_case_value_bytes(&mutation, &shrink_values, &recipe, request.limits)?;
    charge_retained_bytes(
        &mut counters.retained_bytes,
        retained_value_bytes,
        total_byte_limit,
    )?;
    let mut case = new_case(request.seed, index, seed, mutation, shrink_values, recipe);
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
        deadline,
    )?;
    Ok(case)
}

fn new_case(
    operation_seed: u64,
    index: u64,
    seed: u64,
    mutation: Mutation,
    shrink_values: Vec<FieldValue>,
    recipe: Packet,
) -> Case {
    Case {
        operation_seed,
        index,
        seed,
        mutation,
        shrink_values,
        recipe,
        built: None,
        decoded: None,
        outcome: CaseOutcome::Rejected,
        error: None,
        diagnostics: Vec::new(),
    }
}

fn mutation_failure(source: crate::field::Error) -> CaseFailure {
    CaseFailure::with_source(
        "mutation was rejected",
        Classification::new(
            "packet.fuzz_mutation",
            Kind::Packet,
            Some(
                "select a type/range accepted by the target field or retain the rejected case as fuzz evidence",
            ),
        ),
        source,
    )
}

fn build_case(
    case: &mut Case,
    request: &Request,
    builder: &Builder,
    dissector: &Dissector,
    counters: &mut Counters,
    total_byte_limit: u64,
    deadline: &Deadline,
) -> Result<(), Error> {
    match builder.build(
        case.recipe.clone(),
        crate::codec::Context::default(),
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
                deadline.enforce()?;
                let byte_room = total_byte_limit.saturating_sub(counters.retained_bytes);
                case.diagnostics.extend(roundtrip::diagnostic(
                    builder, &built, decoded, request, byte_room,
                ));
            }
            case.built = Some(built);
            case.outcome = CaseOutcome::Built;
            counters.built_cases += 1;
            counters.built_bytes = next_built_bytes;
        }
        Err(source) => {
            case.error = Some(CaseFailure::with_source(
                "mutated packet was rejected",
                Classification::new(
                    "packet.fuzz_build",
                    Kind::Packet,
                    Some(
                        "reproduce the case in permissive offline mode when malformed dependent fields are intentional",
                    ),
                ),
                source,
            ));
        }
    }
    Ok(())
}

fn validate_base_shape(packet: &Packet, max_layers: usize) -> Result<(), Error> {
    if packet.len() > max_layers {
        return Err(Error::InvalidBasePacket {
            reason: BaseFault::Layers {
                layers: packet.len(),
                max_layers,
            },
        });
    }
    let mut fields = 0_usize;
    for layer in packet.iter() {
        fields = fields
            .checked_add(layer.schema().fields.len())
            .ok_or_else(|| Error::InvalidBasePacket {
                reason: BaseFault::FieldCountOverflow,
            })?;
        if fields > MAX_TARGET_FIELDS {
            return Err(Error::InvalidBasePacket {
                reason: BaseFault::SchemaFields { fields },
            });
        }
    }
    Ok(())
}

fn retained_case_value_bytes(
    mutation: &Mutation,
    shrink_values: &[FieldValue],
    recipe: &Packet,
    limits: Limits,
) -> Result<u64, Error> {
    let limit = total_byte_limit(limits);
    let mut total = (mutation.protocol.len() as u64)
        .checked_add(mutation.field.len() as u64)
        .ok_or(byte_limit(u64::MAX, limit))?;
    for value in std::iter::once(&mutation.original)
        .chain(std::iter::once(&mutation.value))
        .chain(shrink_values)
    {
        total = charge_value(total, value, limits)?;
    }
    total
        .checked_add(packet_reflected_value_bytes(recipe, limits)?)
        .ok_or(byte_limit(u64::MAX, limit))
}

fn packet_reflected_value_bytes(packet: &Packet, limits: Limits) -> Result<u64, Error> {
    let mut total = 0_u64;
    for layer in packet.iter() {
        for field in layer.schema().fields {
            let Some(value) = layer.field(field.name) else {
                continue;
            };
            total = charge_value(total, &value, limits)?;
        }
    }
    Ok(total)
}

fn charge_value(total: u64, value: &FieldValue, limits: Limits) -> Result<u64, Error> {
    let limit = total_byte_limit(limits);
    let remaining = limits
        .max_total_bytes
        .saturating_sub(usize::try_from(total).unwrap_or(usize::MAX));
    let size = bounded_value_size(value, remaining, limits.max_list_items)
        .map_err(|reason| value_limit_error(reason, limits))?;
    total
        .checked_add(u64::try_from(size).unwrap_or(u64::MAX))
        .ok_or(byte_limit(u64::MAX, limit))
}

fn value_limit_error(reason: ValueLimit, limits: Limits) -> Error {
    match reason {
        ValueLimit::Bytes => Error::ValueTooLarge {
            limit: limits.max_total_bytes,
        },
        ValueLimit::Items { items } => Error::ValueItems {
            items,
            limit: limits.max_list_items,
        },
        ValueLimit::Nesting => Error::ValueNesting {
            limit: MAX_VALUE_NESTING,
        },
    }
}

fn total_byte_limit(limits: Limits) -> u64 {
    u64::try_from(limits.max_total_bytes).unwrap_or(u64::MAX)
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

fn unresolved_target(field: &ResolvedField, reason: TargetFault) -> Error {
    Error::InvalidTarget {
        target: field.target.clone(),
        reason,
    }
}

fn byte_limit(actual: u64, limit: u64) -> Error {
    Error::ByteLimit { actual, limit }
}

fn resolve_fields(packet: &Packet, requested: &[Target]) -> Result<Vec<ResolvedField>, Error> {
    if requested.is_empty() {
        let mut fields = Vec::new();
        for (layer_index, layer) in packet.iter().enumerate() {
            for field in layer.schema().fields {
                if layer.field(field.name).is_none() {
                    continue;
                }
                if fields.len() >= MAX_TARGET_FIELDS {
                    return Err(Error::InvalidBasePacket {
                        reason: BaseFault::ReflectedFields,
                    });
                }
                fields.push(ResolvedField {
                    target: Target {
                        layer: layer_index,
                        field: field.name.to_owned(),
                    },
                    path: Path::top_level(field.name),
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
            reason: BaseFault::Targets {
                targets: requested.len(),
            },
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
                reason: TargetFault::LayerOutOfRange {
                    layers: packet.len(),
                },
            })?;
        let path = target
            .field
            .parse::<Path>()
            .map_err(|source| Error::TargetField {
                target: target.to_string(),
                source,
            })?;
        let schema = path
            .schema(layer.schema())
            .ok_or_else(|| Error::InvalidTarget {
                target: target.clone(),
                reason: TargetFault::UnregisteredPath,
            })?;
        let value = layer
            .field_path(&path)
            .ok_or_else(|| Error::InvalidTarget {
                target: target.clone(),
                reason: TargetFault::Unreadable,
            })?;
        let kind = if path.is_nested() {
            value.kind()
        } else {
            schema.kind
        };
        fields.push(ResolvedField {
            target: target.clone(),
            protocol: layer.protocol_id().to_string(),
            kind,
            is_derived: schema.derived,
            path,
        });
    }
    Ok(fields)
}

fn strategy_compatible(strategy: Strategy, field: &ResolvedField) -> bool {
    match strategy {
        Strategy::Boundary | Strategy::Random => true,
        Strategy::BitFlip => field.kind == FieldKind::Bytes,
        Strategy::Malformed => field.is_derived,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::Cancellation;
    use crate::error::Classified;
    use crate::layer::Raw;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn cancellation_precedes_expired_preparation_budget_between_cases_and_at_completion() {
        for cases in [1, 2] {
            let signal = Cancellation::default();
            let expired = Arc::new(AtomicBool::new(false));
            let time_expired = expired.clone();
            let started = Instant::now();
            let mut deadline = Deadline::with_time_source(Duration::from_secs(1), move || {
                started
                    + Duration::from_secs(if time_expired.load(Ordering::SeqCst) {
                        2
                    } else {
                        0
                    })
            })
            .with_cancellation(Some(signal.clone()));
            let request = Request {
                cases,
                strategies: vec![Strategy::BitFlip],
                targets: vec!["0.bytes".parse().unwrap()],
                ..Request::default()
            };
            let mut packet = Packet::new();
            packet.push(Raw::new(vec![1, 2, 3]));
            let mut emitted = 0;
            let error = prepare_with_events(
                &request,
                packet,
                crate::protocol::builtin::registry(),
                &mut deadline,
                &mut |_, _| {
                    emitted += 1;
                    signal.cancel();
                    expired.store(true, Ordering::SeqCst);
                    Ok(())
                },
            )
            .expect_err("cancelled preparation must fail");
            assert_eq!(emitted, 1);
            assert_eq!(error.classification().code, "io.cancelled");
        }
    }
}
