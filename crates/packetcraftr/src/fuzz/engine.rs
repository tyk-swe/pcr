// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt::Display;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::Context;
use packetcraftr_core::{
    Packet,
    build::{Builder, BuiltPacket},
    decode::Dissector,
    diagnostic::Diagnostic,
    frame::LinkType,
    fuzz as packet_fuzz,
    registry::Registry,
};

use crate::Error;
use crate::clock::Clock;
use crate::evidence::Budget;
use crate::materialize::{
    build_context, materialize_link_fields, materialize_link_structure, materialize_network_fields,
    require_fixed_width_link_materialization,
};
use crate::policy::Policy;

use super::SYNTHESIZED_ETHERNET_BYTES;
use super::execution::{
    ExecutionEvidence, add_execution_stats, rate_delay, retain_evidence, validate_execution,
    worst_case_duration,
};
use super::model::{
    Case, CaseOutcome, Execution, ExecutionCase, Executor, Options, Result, Stats, Summary,
};

/// Builds and validates all cases offline, then authorizes and executes the campaign.
pub fn run<E, C>(
    request: &packet_fuzz::Request,
    live: Options,
    packet: Packet,
    registry: Arc<Registry>,
    policy: &Policy,
    executor: &mut E,
    clock: &mut C,
) -> std::result::Result<Result, Error>
where
    E: Executor,
    C: Clock,
{
    let mut cases = Vec::new();
    let summary = run_observed(
        request,
        live,
        packet,
        registry,
        policy,
        executor,
        clock,
        |case, _| {
            cases.push(case);
            Ok(())
        },
    )?;
    Ok(Result {
        seed: summary.seed,
        first_case: summary.first_case,
        cases,
        diagnostics: summary.diagnostics,
        stats: summary.stats,
    })
}

/// Executes one fully authorized campaign and publishes cases in deterministic
/// case order as soon as each live outcome is final. The bounded callback
/// worker acknowledges every case before later transmission, preserves its
/// classification on failure, and cannot keep live I/O armed beyond the
/// campaign deadline. A callback that outlives the deadline may finish after
/// this function returns and must therefore own its state.
#[expect(
    clippy::too_many_arguments,
    reason = "live fuzz execution requires the request, approved I/O boundaries, clock, and progressive sink"
)]
pub fn run_with_events<E, C, F>(
    request: &packet_fuzz::Request,
    live: Options,
    packet: Packet,
    registry: Arc<Registry>,
    policy: &Policy,
    executor: &mut E,
    clock: &mut C,
    emit: F,
) -> std::result::Result<Summary, Error>
where
    E: Executor,
    C: Clock,
    F: FnMut(Case) -> std::result::Result<(), crate::BoundaryError> + Send + 'static,
{
    let sink = packetcraftr_core::progress::Sink::new(emit).map_err(|source| Error::Output {
        source: Box::new(source),
    })?;
    run_observed(
        request,
        live,
        packet,
        registry,
        policy,
        executor,
        clock,
        move |case, deadline| match sink.emit(case, deadline) {
            Ok(()) => Ok(()),
            Err(packetcraftr_core::progress::EmitError::Deadline(error)) => Err(error.into()),
            Err(packetcraftr_core::progress::EmitError::Output(source)) => Err(Error::Output {
                source: Box::new(source),
            }),
        },
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "live fuzz execution requires the request, approved I/O boundaries, clock, and progressive sink"
)]
fn run_observed<E, C, F>(
    request: &packet_fuzz::Request,
    live: Options,
    packet: Packet,
    registry: Arc<Registry>,
    policy: &Policy,
    executor: &mut E,
    clock: &mut C,
    mut emit: F,
) -> std::result::Result<Summary, Error>
where
    E: Executor,
    C: Clock,
    F: FnMut(Case, &Deadline) -> std::result::Result<(), Error>,
{
    let live = live.validate()?;
    let mut deadline = Deadline::new(request.limits.max_duration);
    let live_dissector = Dissector::new(Arc::clone(&registry));
    let prepared = prepare_campaign(request, live, packet, &registry, &mut deadline)?;
    authorize_campaign(&prepared, live, policy)?;
    deadline.check()?;

    let PreparedCampaign {
        cases,
        built_case_count,
        ..
    } = prepared;
    ExecutionPhase {
        request,
        live,
        registry,
        live_dissector,
        deadline,
        cases,
        stats: Stats {
            cases_generated: u64::try_from(request.cases).unwrap_or(u64::MAX),
            cases_built: built_case_count,
            ..Stats::default()
        },
        evidence: Budget::default(),
        diagnostics: Vec::new(),
        scheduled_delay: Duration::ZERO,
    }
    .execute(executor, clock, &mut emit)
}

struct PreparedCampaign {
    cases: Vec<Case>,
    built_case_count: u64,
    maximum_wire_bytes: u64,
    requires_permissive_live: bool,
}

fn prepare_campaign(
    request: &packet_fuzz::Request,
    live: Options,
    packet: Packet,
    registry: &Arc<Registry>,
    deadline: &mut Deadline,
) -> std::result::Result<PreparedCampaign, Error> {
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

    let worst_case = worst_case_duration(live, built_cases)?;
    deadline.check_additional(worst_case)?;
    let maximum_wire_bytes = maximum_wire_bytes(request, &cases)?;
    let requires_permissive_live = cases.iter().any(|case| {
        case.prepared
            .built
            .as_ref()
            .is_some_and(|built| built.requires_live_opt_in)
    });
    Ok(PreparedCampaign {
        cases,
        built_case_count,
        maximum_wire_bytes,
        requires_permissive_live,
    })
}

fn maximum_wire_bytes(
    request: &packet_fuzz::Request,
    cases: &[Case],
) -> std::result::Result<u64, Error> {
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
                context: Context::case_index(last_case_index(request)),
            })
    })
}

fn authorize_campaign(
    prepared: &PreparedCampaign,
    live: Options,
    policy: &Policy,
) -> std::result::Result<(), Error> {
    let packets = prepared
        .cases
        .iter()
        .filter_map(|case| {
            case.prepared
                .built
                .as_ref()
                .map(|built| built.packet.clone())
        })
        .collect::<Vec<_>>();
    policy.validate()?;
    policy.authorize_operation(
        u64::try_from(packets.len()).unwrap_or(u64::MAX),
        prepared.maximum_wire_bytes,
    )?;
    policy.authorize_permissive(
        prepared.requires_permissive_live,
        live.allow_permissive_live,
    )?;
    if let Some(destination) = live.destination {
        policy.authorize_destination(destination)?;
    }
    for packet in &packets {
        policy.authorize_packet_destinations(packet)?;
    }
    Ok(())
}

struct ExecutionPhase<'a> {
    request: &'a packet_fuzz::Request,
    live: Options,
    registry: Arc<Registry>,
    live_dissector: Dissector,
    deadline: Deadline,
    cases: Vec<Case>,
    stats: Stats,
    evidence: Budget,
    diagnostics: Vec<Diagnostic>,
    scheduled_delay: Duration,
}

impl ExecutionPhase<'_> {
    fn execute<E, C, F>(
        mut self,
        executor: &mut E,
        clock: &mut C,
        emit: &mut F,
    ) -> std::result::Result<Summary, Error>
    where
        E: Executor,
        C: Clock,
        F: FnMut(Case, &Deadline) -> std::result::Result<(), Error>,
    {
        let cases = std::mem::take(&mut self.cases);
        let mut built_ordinal = 0;
        for mut case in cases {
            let diagnostic_start = self.diagnostics.len();
            if case.prepared.built.is_some() {
                self.pace(built_ordinal, case.prepared.index, clock)?;
                self.deadline.check()?;
                self.execute_case(&mut case, executor)?;
                built_ordinal += 1;
            }
            case.prepared
                .diagnostics
                .extend(self.diagnostics[diagnostic_start..].iter().cloned());
            emit(case, &self.deadline)?;
        }
        self.finish()
    }

    fn pace<C>(
        &mut self,
        ordinal: usize,
        case_index: u64,
        clock: &mut C,
    ) -> std::result::Result<(), Error>
    where
        C: Clock,
    {
        if ordinal == 0 {
            return Ok(());
        }
        let delay = rate_delay(self.live.cases_per_second)?;
        let prospective_scheduled_delay =
            self.scheduled_delay
                .checked_add(delay)
                .ok_or(Error::DurationLimit {
                    actual: Duration::MAX,
                    limit: self.request.limits.max_duration,
                })?;
        self.deadline.start_accounting(delay)?;
        clock.sleep(delay).map_err(|source| Error::Clock {
            context: Context::case_index(case_index),
            message: source.to_string(),
        })?;
        self.deadline.account(delay)?;
        self.scheduled_delay = prospective_scheduled_delay;
        Ok(())
    }

    fn execute_case<E>(
        &mut self,
        case: &mut Case,
        executor: &mut E,
    ) -> std::result::Result<(), Error>
    where
        E: Executor,
    {
        let execution_case = ExecutionCase {
            permit: crate::evidence::ExecutionPermit::new(),
            packet: case.prepared.recipe.clone(),
        };
        self.deadline.start_accounting(Duration::ZERO)?;
        let execution = executor
            .execute(&execution_case, self.live.timeout)
            .map_err(|source| Error::Execution {
                context: Context::case_index(case.prepared.index),
                source: Box::new(source),
            })?;
        if execution.permit != execution_case.permit {
            return Err(Error::InvalidEvidence {
                context: Context::case_index(case.prepared.index),
                message: "executor returned evidence for a different execution permit".to_owned(),
            });
        }
        let expected_live_build = expected_live_build(
            self.request,
            case.prepared.recipe.clone(),
            &self.registry,
            &execution,
        )
        .map_err(|message| Error::InvalidEvidence {
            context: Context::case_index(case.prepared.index),
            message,
        })?;
        if execution.sent.wire_bytes() != &expected_live_build.bytes {
            return Err(Error::InvalidEvidence {
                context: Context::case_index(case.prepared.index),
                message: "executor substituted bytes for the route-materialized case".to_owned(),
            });
        }
        self.deadline.check()?;
        self.deadline.account(execution.stats.elapsed)?;
        validate_execution(
            case,
            &execution,
            self.request.limits.max_packet_bytes,
            &self.deadline,
        )?;
        add_execution_stats(&mut self.stats, &execution.stats, case.prepared.index)?;
        let had_response = !execution.responses.is_empty();
        case.prepared.diagnostics = execution.sent.built().diagnostics.clone();
        case.prepared.decoded = packet_fuzz::dissect_built(
            &self.live_dissector,
            execution.sent.built(),
            self.request.limits,
            &mut case.prepared.diagnostics,
        );
        self.deadline.check()?;
        case.prepared.built = Some(execution.sent.built().clone());
        case.sent = Some(execution.sent.frame().clone());
        case.prepared.diagnostics.extend(execution.diagnostics);
        retain_evidence(
            case,
            ExecutionEvidence {
                responses: execution.responses,
                unmatched: execution.unmatched,
                undecoded: execution.undecoded,
            },
            self.live.limits,
            &mut self.evidence,
            &mut self.diagnostics,
            &self.deadline,
        )?;
        case.outcome = if had_response {
            CaseOutcome::Response
        } else {
            CaseOutcome::Timeout
        };
        self.deadline.check()?;
        Ok(())
    }

    fn finish(mut self) -> std::result::Result<Summary, Error> {
        self.stats.elapsed = self.stats.elapsed.checked_add(self.scheduled_delay).ok_or(
            Error::StatisticsOverflow {
                context: Context::case_index(last_case_index(self.request)),
            },
        )?;
        self.deadline.check()?;

        Ok(Summary {
            seed: self.request.seed,
            first_case: self.request.first_case,
            diagnostics: Vec::new(),
            stats: self.stats,
        })
    }
}

fn expected_live_build(
    request: &packet_fuzz::Request,
    mut packet: Packet,
    registry: &Arc<Registry>,
    execution: &Execution,
) -> std::result::Result<BuiltPacket, String> {
    let route = execution.sent.route();
    stringify(materialize_network_fields(&mut packet, &route.plan))?;
    stringify(materialize_link_structure(&mut packet, &route.plan))?;

    let context = build_context(&route.plan);
    let builder = Builder::new(Arc::clone(registry));
    let preliminary = build_packet(&builder, packet.clone(), context.clone(), request)?;
    let preliminary_len = preliminary.bytes.len();

    let built = if stringify(materialize_link_fields(&mut packet, route))? {
        build_packet(&builder, packet, context, request)?
    } else {
        preliminary
    };
    stringify(require_fixed_width_link_materialization(
        preliminary_len,
        built.bytes.len(),
    ))?;
    Ok(built)
}

fn build_packet(
    builder: &Builder,
    packet: Packet,
    context: packetcraftr_core::build::Context,
    request: &packet_fuzz::Request,
) -> std::result::Result<BuiltPacket, String> {
    stringify(builder.build(packet, context, request.build.clone()))
}

fn last_case_index(request: &packet_fuzz::Request) -> u64 {
    request
        .first_case
        .saturating_add(u64::try_from(request.cases.saturating_sub(1)).unwrap_or(u64::MAX))
}

fn stringify<T, E: Display>(result: std::result::Result<T, E>) -> std::result::Result<T, String> {
    result.map_err(|source| source.to_string())
}
