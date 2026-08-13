// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::{
    Packet,
    build::{Builder, Context as BuildContext, Result as BuiltPacket},
    decode::Decoder as Dissector,
    fuzz as packet_fuzz,
    registry::Registry,
};

use crate::clock::Clock;
use crate::materialize::{
    build_context, materialize_link_fields, materialize_link_structure, materialize_network_fields,
    patch_builtin_ethernet, require_fixed_width_link_materialization,
};
use crate::probe::evidence::EvidenceBudget;

use super::boundary::{FuzzAuthorizer, FuzzCaseExecution, FuzzExecutionCase, FuzzExecutor};
use super::error::{FuzzError, duration_limit};
use super::execution::{
    ExecutionEvidence, add_execution_stats, rate_delay, retain_evidence, validate_execution,
    worst_case_duration,
};
use super::request::LiveOptions;
use super::result::{Case, CaseOutcome, Mode, Result, Stats};
use super::{
    SYNTHESIZED_ETHERNET_BYTES,
    decode::{dissect_built, has_link_root},
};

/// Builds and validates all cases offline, then authorizes and executes the campaign.
///
/// # Panics
///
/// Panics only if an internally selected case was never built; input errors return
/// [`FuzzError`].
pub fn run<A, E, C>(
    request: &packet_fuzz::Request,
    live: LiveOptions,
    packet: Packet,
    registry: Arc<Registry>,
    authorizer: &mut A,
    executor: &mut E,
    clock: &mut C,
) -> std::result::Result<Result, FuzzError>
where
    A: FuzzAuthorizer,
    E: FuzzExecutor,
    C: Clock,
{
    let live = live.validate()?;
    let mut deadline = Deadline::new(request.limits.max_duration);
    let live_dissector = Dissector::new(Arc::clone(&registry));
    let campaign =
        packet_fuzz::Campaign::prepare(request, packet, Arc::clone(&registry), &mut deadline)?;
    let built_case_count = campaign.built_case_count();
    let retained_byte_count = campaign.retained_byte_count();
    let mut cases = campaign
        .into_cases()
        .into_iter()
        .map(Case::from)
        .collect::<Vec<_>>();
    let built_indices = cases
        .iter()
        .enumerate()
        .filter_map(|(index, case)| case.built.is_some().then_some(index))
        .collect::<Vec<_>>();

    let worst_case = worst_case_duration(live, built_indices.len())?;
    deadline
        .check_additional(worst_case)
        .map_err(duration_limit)?;

    let maximum_wire_bytes = cases.iter().try_fold(0_u64, |total, case| {
        let Some(built) = &case.built else {
            return Ok(total);
        };
        let overhead = if has_link_root(&built.packet) {
            0
        } else {
            SYNTHESIZED_ETHERNET_BYTES
        };
        total
            .checked_add(u64::try_from(built.bytes.len()).unwrap_or(u64::MAX))
            .and_then(|value| value.checked_add(overhead))
            .ok_or(FuzzError::ByteLimit {
                actual: u64::MAX,
                limit: u64::try_from(request.limits.max_total_bytes).unwrap_or(u64::MAX),
            })
    })?;
    if maximum_wire_bytes > u64::try_from(request.limits.max_total_bytes).unwrap_or(u64::MAX) {
        return Err(FuzzError::ByteLimit {
            actual: maximum_wire_bytes,
            limit: u64::try_from(request.limits.max_total_bytes).unwrap_or(u64::MAX),
        });
    }
    let requires_malformed_live = cases.iter().any(|case| {
        case.built
            .as_ref()
            .is_some_and(|built| built.requires_live_opt_in)
    });
    if requires_malformed_live && !live.allow_malformed_live {
        return Err(FuzzError::MalformedLiveOptInRequired);
    }
    let packets = built_indices
        .iter()
        .map(|index| {
            cases[*index]
                .built
                .as_ref()
                .expect("selected built case")
                .packet
                .clone()
        })
        .collect::<Vec<_>>();
    if !packets.is_empty() {
        authorizer.authorize_operation(
            &packets,
            live.destination,
            maximum_wire_bytes,
            requires_malformed_live,
        )?;
    }
    deadline.check().map_err(duration_limit)?;

    let mut stats = Stats {
        cases_generated: u64::try_from(request.cases).unwrap_or(u64::MAX),
        cases_built: built_case_count,
        ..Stats::default()
    };
    let retained_byte_count =
        usize::try_from(retained_byte_count).map_err(|_| FuzzError::ByteLimit {
            actual: retained_byte_count,
            limit: u64::try_from(request.limits.max_total_bytes).unwrap_or(u64::MAX),
        })?;
    let mut evidence_limits = request.limits;
    evidence_limits.max_evidence_bytes = evidence_limits.max_evidence_bytes.min(
        request
            .limits
            .max_total_bytes
            .saturating_sub(retained_byte_count),
    );
    let mut evidence = EvidenceBudget::default();
    let mut operation_diagnostics = Vec::new();
    let mut scheduled_delay = Duration::ZERO;
    for (ordinal, case_index) in built_indices.into_iter().enumerate() {
        let case = &mut cases[case_index];
        if ordinal != 0 {
            let delay = rate_delay(live.cases_per_second)?;
            let prospective_scheduled_delay =
                scheduled_delay
                    .checked_add(delay)
                    .ok_or(FuzzError::DurationLimit {
                        actual: Duration::MAX,
                        limit: request.limits.max_duration,
                    })?;
            deadline.start_accounting(delay).map_err(duration_limit)?;
            clock.sleep(delay).map_err(|source| FuzzError::Clock {
                case_index: case.index,
                message: source.to_string(),
            })?;
            deadline.account(delay).map_err(duration_limit)?;
            scheduled_delay = prospective_scheduled_delay;
        }
        deadline.check().map_err(duration_limit)?;
        let execution_case = FuzzExecutionCase {
            permit: crate::evidence::ExecutionPermit::new(),
            packet: case.recipe.clone(),
        };
        deadline
            .start_accounting(Duration::ZERO)
            .map_err(duration_limit)?;
        let execution = executor
            .execute(&execution_case, live.timeout)
            .map_err(|source| FuzzError::Execution {
                case_index: case.index,
                source,
            })?;
        if execution.permit != execution_case.permit {
            return Err(FuzzError::InvalidEvidence {
                case_index: case.index,
                message: "executor returned evidence for a different execution permit".to_owned(),
            });
        }
        let expected_live_build =
            expected_live_build(request, case.recipe.clone(), &registry, &execution).map_err(
                |message| FuzzError::InvalidEvidence {
                    case_index: case.index,
                    message,
                },
            )?;
        if execution.sent.wire_bytes() != &expected_live_build.bytes {
            return Err(FuzzError::InvalidEvidence {
                case_index: case.index,
                message: "executor substituted bytes for the route-materialized case".to_owned(),
            });
        }
        deadline.check().map_err(duration_limit)?;
        deadline
            .account(execution.stats.elapsed)
            .map_err(duration_limit)?;
        validate_execution(case, &execution, request.limits, live.timeout, &deadline)?;
        add_execution_stats(&mut stats, &execution.stats, case.index)?;
        if stats.bytes > u64::try_from(request.limits.max_total_bytes).unwrap_or(u64::MAX) {
            return Err(FuzzError::ByteLimit {
                actual: stats.bytes,
                limit: u64::try_from(request.limits.max_total_bytes).unwrap_or(u64::MAX),
            });
        }
        let had_response = !execution.responses.is_empty();
        case.diagnostics = execution.sent.built().diagnostics.clone();
        case.decoded = dissect_built(
            &live_dissector,
            execution.sent.built(),
            request.limits,
            &mut case.diagnostics,
        );
        deadline.check().map_err(duration_limit)?;
        case.built = Some(execution.sent.built().clone());
        case.sent = Some(execution.sent.frame().clone());
        case.diagnostics.extend(execution.diagnostics);
        retain_evidence(
            case,
            ExecutionEvidence {
                responses: execution.responses,
                unmatched: execution.unmatched,
                undecoded: execution.undecoded,
            },
            evidence_limits,
            &mut evidence,
            &mut operation_diagnostics,
            &deadline,
        )?;
        case.outcome = if had_response {
            CaseOutcome::Response
        } else {
            CaseOutcome::Timeout
        };
        deadline.check().map_err(duration_limit)?;
    }
    stats.elapsed =
        stats
            .elapsed
            .checked_add(scheduled_delay)
            .ok_or(FuzzError::StatisticsOverflow {
                case_index: request.first_case.saturating_add(
                    u64::try_from(request.cases.saturating_sub(1)).unwrap_or(u64::MAX),
                ),
            })?;
    deadline.check().map_err(duration_limit)?;

    Ok(Result {
        mode: Mode::Live,
        seed: request.seed,
        first_case: request.first_case,
        cases,
        diagnostics: operation_diagnostics,
        stats,
    })
}

fn expected_live_build(
    request: &packet_fuzz::Request,
    mut packet: Packet,
    registry: &Arc<Registry>,
    execution: &FuzzCaseExecution,
) -> std::result::Result<BuiltPacket, String> {
    let route = execution.sent.route();
    materialize_network_fields(&mut packet, &route.plan).map_err(|source| source.to_string())?;
    materialize_link_structure(&mut packet, &route.plan).map_err(|source| source.to_string())?;

    let context = build_context(&route.plan);
    let builder = Builder::new(Arc::clone(registry));
    let mut preliminary = build_packet(&builder, packet.clone(), context.clone(), request)?;
    let preliminary_len = preliminary.bytes.len();

    if materialize_link_fields(&mut packet, route).map_err(|source| source.to_string())? {
        if patch_builtin_ethernet(registry, &mut preliminary, &packet) {
            require_fixed_width_link_materialization(preliminary_len, preliminary.bytes.len())
                .map_err(|source| source.to_string())?;
            return Ok(preliminary);
        }
        let materialized = build_packet(&builder, packet, context, request)?;
        require_fixed_width_link_materialization(preliminary_len, materialized.bytes.len())
            .map_err(|source| source.to_string())?;
        return Ok(materialized);
    }

    require_fixed_width_link_materialization(preliminary_len, preliminary.bytes.len())
        .map_err(|source| source.to_string())?;
    Ok(preliminary)
}

fn build_packet(
    builder: &Builder,
    packet: Packet,
    context: BuildContext,
    request: &packet_fuzz::Request,
) -> std::result::Result<BuiltPacket, String> {
    builder
        .build(packet, context, request.build.clone())
        .map_err(|source| source.to_string())
}
