// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt::Display;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::{
    Packet,
    build::{Builder, BuiltPacket},
    decode::Dissector,
    diagnostic::Diagnostic,
    frame::LinkType,
    fuzz as packet_fuzz,
    registry::Registry,
};

use crate::clock::Clock;
use crate::evidence::Budget;
use crate::materialize::{
    build_context, materialize_link_fields, materialize_link_structure, materialize_network_fields,
    require_fixed_width_link_materialization,
};
use crate::probe::runner::sink_observer;

use super::SYNTHESIZED_ETHERNET_BYTES;
use super::boundary::{Execution, ExecutionCase, Executor};
use super::error::{Error, duration_limit};
use super::execution::{
    ExecutionEvidence, add_execution_stats, rate_delay, retain_evidence, validate_execution,
    worst_case_duration,
};
use super::request::LiveOptions;
use super::result::{Case, CaseOutcome, Result, Stats, Summary};
use crate::authorization::{Authorizer, DeclaredPackets, Operation, PermissiveLive, WireBudget};

/// Builds and validates all cases offline, then authorizes and executes the campaign.
pub fn run<A, E, C>(
    request: &packet_fuzz::Request,
    live: LiveOptions,
    packet: Packet,
    registry: Arc<Registry>,
    authorizer: &mut A,
    executor: &mut E,
    clock: &mut C,
) -> std::result::Result<Result, Error>
where
    A: Authorizer,
    E: Executor,
    C: Clock,
{
    let mut cases = Vec::new();
    let summary = run_observed(
        RunInput {
            request,
            live,
            packet,
            registry,
        },
        authorizer,
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
/// case order as soon as each live outcome is final. The process-budgeted
/// callback worker acknowledges every case before later transmission and
/// preserves its classification on failure. The campaign deadline bounds
/// publisher waiting and live I/O, not callback execution; an outliving
/// callback holds its worker permit until it returns.
#[expect(
    clippy::too_many_arguments,
    reason = "live fuzz execution requires the request, approved I/O boundaries, clock, and progressive sink"
)]
pub fn run_with_events<A, E, C, F>(
    request: &packet_fuzz::Request,
    live: LiveOptions,
    packet: Packet,
    registry: Arc<Registry>,
    authorizer: &mut A,
    executor: &mut E,
    clock: &mut C,
    emit: F,
) -> std::result::Result<Summary, Error>
where
    A: Authorizer,
    E: Executor,
    C: Clock,
    F: FnMut(Case) -> std::result::Result<(), crate::BoundaryError> + Send + 'static,
{
    let observe = sink_observer(emit, duration_limit, |source| Error::Output { source })?;
    run_observed(
        RunInput {
            request,
            live,
            packet,
            registry,
        },
        authorizer,
        executor,
        clock,
        observe,
    )
}

struct RunInput<'a> {
    request: &'a packet_fuzz::Request,
    live: LiveOptions,
    packet: Packet,
    registry: Arc<Registry>,
}

fn run_observed<A, E, C, F>(
    input: RunInput<'_>,
    authorizer: &mut A,
    executor: &mut E,
    clock: &mut C,
    mut emit: F,
) -> std::result::Result<Summary, Error>
where
    A: Authorizer,
    E: Executor,
    C: Clock,
    F: FnMut(Case, &Deadline) -> std::result::Result<(), Error>,
{
    let RunInput {
        request,
        live,
        packet,
        registry,
    } = input;
    let live = live.validate()?;
    let mut deadline = Deadline::new(request.limits.max_duration);
    let live_dissector = Dissector::new(Arc::clone(&registry));
    let prepared = prepare_campaign(request, live, packet, &registry, &mut deadline)?;
    authorize_campaign(&prepared, live, authorizer)?;
    deadline.check().map_err(duration_limit)?;

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
    requires_malformed_live: bool,
}

fn prepare_campaign(
    request: &packet_fuzz::Request,
    live: LiveOptions,
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
    deadline
        .check_additional(worst_case)
        .map_err(duration_limit)?;
    let maximum_wire_bytes = maximum_wire_bytes(request, &cases)?;
    let requires_malformed_live = cases.iter().any(|case| {
        case.prepared
            .built
            .as_ref()
            .is_some_and(|built| built.requires_live_opt_in)
    });
    if requires_malformed_live && !live.allow_malformed_live {
        return Err(Error::MalformedLiveOptInRequired);
    }

    Ok(PreparedCampaign {
        cases,
        built_case_count,
        maximum_wire_bytes,
        requires_malformed_live,
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
                case_index: last_case_index(request),
            })
    })
}

fn authorize_campaign<A>(
    prepared: &PreparedCampaign,
    live: LiveOptions,
    authorizer: &mut A,
) -> std::result::Result<(), Error>
where
    A: Authorizer,
{
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

struct ExecutionPhase<'a> {
    request: &'a packet_fuzz::Request,
    live: LiveOptions,
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
                self.deadline.check().map_err(duration_limit)?;
                self.execute_case(&mut case, executor)?;
                #[expect(
                    clippy::arithmetic_side_effects,
                    reason = "one increment per case in `cases`, so the ordinal cannot exceed \
                              `cases.len()`"
                )]
                {
                    built_ordinal += 1;
                }
            }
            #[expect(
                clippy::indexing_slicing,
                reason = "`diagnostic_start` is `self.diagnostics.len()` read at the top of this \
                          iteration and the vector is only appended to, so the range is in bounds"
            )]
            let new_diagnostics = &self.diagnostics[diagnostic_start..];
            case.prepared
                .diagnostics
                .extend(new_diagnostics.iter().cloned());
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
        self.deadline
            .start_accounting(delay)
            .map_err(duration_limit)?;
        clock.sleep(delay).map_err(|source| Error::Clock {
            case_index,
            message: source.to_string(),
        })?;
        self.deadline.account(delay).map_err(duration_limit)?;
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
        self.deadline
            .start_accounting(Duration::ZERO)
            .map_err(duration_limit)?;
        let execution = executor
            .execute(&execution_case, self.live.timeout)
            .map_err(|source| Error::Execution {
                case_index: case.prepared.index,
                source,
            })?;
        if execution.permit != execution_case.permit {
            return Err(Error::InvalidEvidence {
                case_index: case.prepared.index,
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
            case_index: case.prepared.index,
            message,
        })?;
        if execution.sent.wire_bytes() != &expected_live_build.bytes {
            return Err(Error::InvalidEvidence {
                case_index: case.prepared.index,
                message: "executor substituted bytes for the route-materialized case".to_owned(),
            });
        }
        self.deadline.check().map_err(duration_limit)?;
        self.deadline
            .account(execution.stats.elapsed)
            .map_err(duration_limit)?;
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
        self.deadline.check().map_err(duration_limit)?;
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
        self.deadline.check().map_err(duration_limit)?;
        Ok(())
    }

    fn finish(mut self) -> std::result::Result<Summary, Error> {
        self.stats.elapsed = self.stats.elapsed.checked_add(self.scheduled_delay).ok_or(
            Error::StatisticsOverflow {
                case_index: last_case_index(self.request),
            },
        )?;
        self.deadline.check().map_err(duration_limit)?;

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
