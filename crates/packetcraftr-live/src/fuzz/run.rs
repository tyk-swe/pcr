// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use packetcraftr_packet::budget::Deadline;
use packetcraftr_packet::{
    Packet, decode::Decoder as Dissector, fuzz as packet_fuzz, registry::Registry,
};

use crate::clock::Clock;
use crate::probe::evidence::EvidenceBudget;

use super::boundary::{FuzzAuthorizer, FuzzExecutionCase, FuzzExecutor};
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
    let build_registry = Arc::clone(&registry);
    let campaign = packet_fuzz::Campaign::prepare(request, packet, registry, &mut deadline)?;
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
            .checked_add(built.bytes.len() as u64)
            .and_then(|value| value.checked_add(overhead))
            .ok_or(FuzzError::ByteLimit {
                actual: u64::MAX,
                limit: request.limits.max_total_bytes as u64,
            })
    })?;
    if maximum_wire_bytes > request.limits.max_total_bytes as u64 {
        return Err(FuzzError::ByteLimit {
            actual: maximum_wire_bytes,
            limit: request.limits.max_total_bytes as u64,
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
        cases_generated: request.cases as u64,
        cases_built: built_case_count,
        ..Stats::default()
    };
    let retained_byte_count =
        usize::try_from(retained_byte_count).map_err(|_| FuzzError::ByteLimit {
            actual: retained_byte_count,
            limit: request.limits.max_total_bytes as u64,
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
        let authorized_build = case.built.clone().expect("selected built case");
        let execution_case = FuzzExecutionCase::from_prepared(
            case.index,
            case.seed,
            authorized_build,
            Arc::clone(&build_registry),
            request.build.clone(),
        );
        deadline
            .start_accounting(Duration::ZERO)
            .map_err(duration_limit)?;
        let execution = executor
            .execute(&execution_case, live.timeout)
            .map_err(|source| FuzzError::Execution {
                case_index: case.index,
                source,
            })?;
        deadline.check().map_err(duration_limit)?;
        deadline
            .account(execution.stats().elapsed)
            .map_err(duration_limit)?;
        validate_execution(case, &execution, request.limits, live.timeout, &deadline)?;
        add_execution_stats(&mut stats, execution.stats(), case.index)?;
        if stats.bytes > request.limits.max_total_bytes as u64 {
            return Err(FuzzError::ByteLimit {
                actual: stats.bytes,
                limit: request.limits.max_total_bytes as u64,
            });
        }
        let had_response = !execution.responses().is_empty();
        case.diagnostics = execution.sent().built().diagnostics.clone();
        case.decoded = dissect_built(
            &live_dissector,
            execution.sent().built(),
            request.limits,
            &mut case.diagnostics,
        );
        deadline.check().map_err(duration_limit)?;
        case.built = Some(execution.sent().built().clone());
        case.sent = Some(execution.sent().evidence().clone());
        case.diagnostics
            .extend(execution.diagnostics().iter().cloned());
        retain_evidence(
            case,
            ExecutionEvidence {
                responses: execution
                    .responses()
                    .iter()
                    .map(|response| response.response().frame.clone())
                    .collect(),
                unmatched: execution
                    .unmatched()
                    .iter()
                    .map(|response| response.response().frame.clone())
                    .collect(),
                undecoded: execution
                    .undecoded()
                    .iter()
                    .map(|capture| capture.frame().clone())
                    .collect(),
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
                case_index: request
                    .first_case
                    .saturating_add(request.cases.saturating_sub(1) as u64),
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
