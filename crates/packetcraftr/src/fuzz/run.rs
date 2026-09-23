// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::{
    build::Builder, frame::LinkType, fuzz as packet_fuzz, packet::Packet, registry::Registry,
};

use crate::clock::Clock;
use crate::execution::{Context, Grant};
use crate::preparation::exact_bytes;
use crate::probe::runner::sink_observer;
use crate::progress::Runtime;

use super::SYNTHESIZED_ETHERNET_BYTES;
use super::error::{CaseErrors, Error, duration_limit};
use super::evidence::{Recorder, validate_execution};
use super::execution::{Execution, ExecutionCase};
use super::plan::{rate_delay, worst_case_duration};
use super::{Case, LiveOptions, Report, Stats, Summary};
use crate::policy::{Authorizer, DeclaredPackets, Operation, PermissiveLive, WireBudget};
use crate::probe::Executor;

/// Builds and validates all cases offline, then authorizes and executes the campaign.
pub fn run<A, E, C>(
    input: RunInput<'_>,
    authorizer: &mut A,
    executor: &mut E,
    clock: &mut C,
) -> Result<Report, Error>
where
    A: Authorizer,
    E: Executor<ExecutionCase>,
    C: Clock,
{
    let mut cases = Vec::new();
    let summary = run_observed(input, authorizer, executor, clock, |case, _| {
        cases.push(case);
        Ok(())
    })?;
    Ok(Report {
        seed: summary.seed,
        first_case: summary.first_case,
        cases,
        stats: summary.stats,
    })
}

/// Executes one fully authorized campaign and publishes cases in deterministic
/// case order as soon as each live outcome is final. The runtime-budgeted
/// callback worker acknowledges every case before later transmission and
/// preserves its classification on failure. The campaign deadline bounds
/// publisher waiting and live I/O, not callback execution; an outliving
/// callback holds its worker permit until it returns.
pub fn run_with_events<A, E, C, F>(
    input: RunInput<'_>,
    authorizer: &mut A,
    executor: &mut E,
    clock: &mut C,
    runtime: &Runtime,
    emit: F,
) -> Result<Summary, Error>
where
    A: Authorizer,
    E: Executor<ExecutionCase>,
    C: Clock,
    F: FnMut(Case) -> Result<(), crate::BoundaryError> + Send + 'static,
{
    let observe = sink_observer(runtime, emit, duration_limit, |source| Error::Output {
        source,
    })?;
    run_observed(input, authorizer, executor, clock, observe)
}

/// Generates an offline campaign and publishes each case through a bounded
/// callback worker admitted by `runtime`, without any live execution.
pub fn run_offline_with_events<F>(
    request: &packet_fuzz::Request,
    packet: Packet,
    registry: Arc<Registry>,
    runtime: &Runtime,
    emit: F,
) -> Result<packet_fuzz::Summary, packet_fuzz::Error>
where
    F: FnMut(packet_fuzz::Case) -> Result<(), crate::BoundaryError> + Send + 'static,
{
    let observe = sink_observer(runtime, emit, packet_fuzz::Error::from, |source| {
        packet_fuzz::Error::Output { source }
    })?;
    packet_fuzz::run_observed(request, packet, registry, observe)
}

pub struct RunInput<'a> {
    /// The offline campaign definition.
    pub request: &'a packet_fuzz::Request,
    /// Pacing, timeout, and retention limits for live execution.
    pub live: LiveOptions,
    /// The template packet every case mutates.
    pub packet: Packet,
    pub registry: Arc<Registry>,
}

fn run_observed<A, E, C, F>(
    input: RunInput<'_>,
    authorizer: &mut A,
    executor: &mut E,
    clock: &mut C,
    mut emit: F,
) -> Result<Summary, Error>
where
    A: Authorizer,
    E: Executor<ExecutionCase>,
    C: Clock,
    F: FnMut(Case, &Deadline) -> Result<(), Error>,
{
    let RunInput {
        request,
        live,
        packet,
        registry,
    } = input;
    let mut deadline =
        Deadline::new(request.limits.max_duration).with_cancellation(clock.cancellation());
    deadline.check_cancelled()?;
    live.validate()?;
    let prepared = prepare_campaign(request, live, packet, &registry, &mut deadline)?;
    deadline.enforce()?;
    authorize_campaign(&prepared, live, authorizer)?;
    deadline.enforce()?;

    let PreparedCampaign {
        cases,
        built_case_count,
        ..
    } = prepared;
    let delay = rate_delay(live.cases_per_second)?;
    let builder = Builder::new(Arc::clone(&registry));
    let mut recorder = Recorder::new(Arc::clone(&registry), request.limits, live.limits);
    let mut context = Context::new(&mut deadline, clock, CaseErrors);
    let mut executed_before = false;
    for mut case in cases {
        let case_index = case.prepared.index;
        context.enforce(case_index)?;
        if case.prepared.built.is_some() {
            // Cases per second: every built case after the first waits one
            // case's share of a second.
            if executed_before {
                context.pace(case_index, delay)?;
            }
            executed_before = true;
            let (execution, _) = context.step(
                case_index,
                live.timeout,
                &mut *executor,
                |executor, grant| {
                    executor.execute(&ExecutionCase {
                        permit: grant.permit,
                        packet: case.prepared.recipe.clone(),
                        timeout: grant.timeout,
                    })
                },
                |_, execution, grant, deadline| {
                    validate_case(request, &builder, &case, execution, grant, deadline)
                },
            )?;
            recorder.record(&mut case, execution, context.deadline())?;
        }
        recorder.publish_diagnostics(&mut case)?;
        emit(case, context.deadline())?;
    }
    context.enforce(last_case_index(request))?;

    let crate::Stats {
        packets_attempted,
        packets_completed,
        bytes,
        elapsed,
        capture,
    } = context.into_stats();
    Ok(Summary {
        seed: request.seed,
        first_case: request.first_case,
        stats: Stats {
            cases_generated: u64::try_from(request.cases).unwrap_or(u64::MAX),
            cases_built: built_case_count,
            packets_attempted,
            packets_completed,
            bytes,
            elapsed,
            capture,
        },
    })
}

struct PreparedCampaign {
    cases: Vec<Case>,
    built_case_count: u64,
    maximum_wire_bytes: u64,
    requires_malformed_live: bool,
}

fn prepare_campaign(
    request: &packet_fuzz::Request,
    live: LiveOptions,
    packet: Packet,
    registry: &Arc<Registry>,
    deadline: &mut Deadline,
) -> Result<PreparedCampaign, Error> {
    let campaign = packet_fuzz::Campaign::prepare(request, packet, Arc::clone(registry), deadline)?;
    let cases = campaign
        .into_cases()
        .into_iter()
        .map(Case::from)
        .collect::<Vec<_>>();
    let built_cases = cases
        .iter()
        .filter(|case| case.prepared.built.is_some())
        .count();
    let built_case_count = u64::try_from(built_cases).unwrap_or(u64::MAX);

    deadline.enforce()?;
    let worst_case = worst_case_duration(live, built_cases)?;
    deadline
        .check_additional(worst_case)
        .map_err(duration_limit)?;
    let maximum_wire_bytes = maximum_wire_bytes(request, &cases)?;
    // Whether the opt-in is *needed* is decided here; whether it was *given*
    // is decided by `authorize_campaign` on the next line, so the destination
    // gate runs first and `policy.allow_permissive_packets` also applies.
    let requires_malformed_live = cases.iter().any(|case| {
        case.prepared
            .built
            .as_ref()
            .is_some_and(|built| built.requires_live_opt_in)
    });

    Ok(PreparedCampaign {
        cases,
        built_case_count,
        maximum_wire_bytes,
        requires_malformed_live,
    })
}

fn maximum_wire_bytes(request: &packet_fuzz::Request, cases: &[Case]) -> Result<u64, Error> {
    cases.iter().try_fold(0_u64, |total, case| {
        let Some(built) = &case.prepared.built else {
            return Ok(total);
        };
        let overhead = match packet_fuzz::packet_link_type(&built.packet) {
            Some(
                LinkType::ETHERNET
                | LinkType::NULL
                | LinkType::LOOP
                | LinkType::LINUX_SLL
                | LinkType::LINUX_SLL2,
            ) => 0,
            _ => SYNTHESIZED_ETHERNET_BYTES,
        };
        total
            .checked_add(u64::try_from(built.bytes.len()).unwrap_or(u64::MAX))
            .and_then(|value| value.checked_add(overhead))
            .ok_or(Error::StatisticsOverflow {
                case_index: last_case_index(request),
            })
    })
}

/// Authorizes the declared campaign. Fuzz deliberately stays outside
/// `target::admit_operation`: there is no declared target to resolve, and the
/// caller's cancellation-aware `enforce` brackets let an authorizer refusal
/// outrank a deadline spent during the call — `approve_operation`'s
/// elapsed-only gate would report the deadline first.
fn authorize_campaign<A>(
    prepared: &PreparedCampaign,
    live: LiveOptions,
    authorizer: &mut A,
) -> Result<(), Error>
where
    A: Authorizer,
{
    let packets = prepared
        .cases
        .iter()
        .filter_map(|case| case.prepared.built.as_ref().map(|built| &built.packet))
        .collect::<Vec<_>>();
    // Unconditional: a campaign with no buildable case still has to clear
    // policy validation and the destination gate before anything else runs.
    let permissive_live = if prepared.requires_malformed_live {
        PermissiveLive::Required {
            allowed: live.allow_malformed_live,
        }
    } else {
        PermissiveLive::NotRequired
    };
    authorizer.authorize_operation(Operation::Declared(DeclaredPackets::new(
        WireBudget::new(prepared.built_case_count, prepared.maximum_wire_bytes),
        &packets,
        live.destination,
        permissive_live,
    )))?;
    Ok(())
}

/// Judges one case's evidence before any of it is recorded: the executor must
/// have sent exactly the route-materialized authorized case, within the
/// campaign's packet limit, and every response must arrive within the
/// granted, already clipped, timeout.
fn validate_case(
    request: &packet_fuzz::Request,
    builder: &Builder,
    case: &Case,
    execution: &Execution,
    grant: Grant,
    deadline: &Deadline,
) -> Result<(), Error> {
    let route = execution.sent.route();
    let expected = exact_bytes(builder, &request.build, case.prepared.recipe.clone(), route)
        .map_err(|source| Error::UnverifiableRoute {
            case_index: case.prepared.index,
            source,
        })?;
    if execution.sent.wire_bytes() != &expected {
        return Err(Error::InvalidEvidence {
            case_index: case.prepared.index,
            message: "executor substituted bytes for the route-materialized case".to_owned(),
        });
    }
    validate_execution(
        case,
        execution,
        grant.timeout,
        request.limits.max_packet_bytes,
        deadline,
    )
}

fn last_case_index(request: &packet_fuzz::Request) -> u64 {
    request
        .first_case
        .saturating_add(u64::try_from(request.cases.saturating_sub(1)).unwrap_or(u64::MAX))
}
