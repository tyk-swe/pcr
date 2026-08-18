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
    fuzz as packet_fuzz,
    registry::Registry,
};

use crate::clock::Clock;
use crate::evidence::Budget;
use crate::materialize::{
    build_context, materialize_link_fields, materialize_link_structure, materialize_network_fields,
    patch_builtin_ethernet, require_fixed_width_link_materialization,
};

use super::boundary::{Authorizer, Execution, ExecutionCase, Executor};
use super::error::{Error, duration_limit};
use super::execution::{
    ExecutionEvidence, add_execution_stats, rate_delay, retain_evidence, validate_execution,
    worst_case_duration,
};
use super::request::LiveOptions;
use super::result::{Case, CaseOutcome, Result, Stats};
use super::{
    SYNTHESIZED_ETHERNET_BYTES,
    decode::{dissect_built, has_link_root},
};

/// Builds and validates all cases offline, then authorizes and executes the campaign.
///
/// # Panics
///
/// Panics only if an internally selected case was never built; input errors return
/// [`Error`].
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
    let live = live.validate()?;
    let mut deadline = Deadline::new(request.limits.max_duration);
    let live_dissector = Dissector::new(Arc::clone(&registry));
    let prepared = prepare_campaign(request, live, packet, &registry, &mut deadline)?;
    authorize_campaign(&prepared, live, authorizer)?;
    deadline.check().map_err(duration_limit)?;

    let PreparedCampaign {
        cases,
        built_indices,
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
    .execute(built_indices, executor, clock)
}

struct PreparedCampaign {
    cases: Vec<Case>,
    built_indices: Vec<usize>,
    built_case_count: u64,
    maximum_wire_bytes: u64,
    requires_live_opt_in: bool,
}

fn prepare_campaign(
    request: &packet_fuzz::Request,
    live: LiveOptions,
    packet: Packet,
    registry: &Arc<Registry>,
    deadline: &mut Deadline,
) -> std::result::Result<PreparedCampaign, Error> {
    let campaign = packet_fuzz::Campaign::prepare(request, packet, Arc::clone(registry), deadline)?;
    let built_case_count = campaign.built_case_count();
    let cases = campaign
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
    let maximum_wire_bytes = maximum_wire_bytes(request, &cases)?;
    let requires_live_opt_in = cases.iter().any(|case| {
        case.built
            .as_ref()
            .is_some_and(|built| built.requires_live_opt_in)
    });
    if requires_live_opt_in && !live.confirm_live_opt_in {
        return Err(Error::LiveOptInRequired);
    }

    Ok(PreparedCampaign {
        cases,
        built_indices,
        built_case_count,
        maximum_wire_bytes,
        requires_live_opt_in,
    })
}

fn maximum_wire_bytes(
    request: &packet_fuzz::Request,
    cases: &[Case],
) -> std::result::Result<u64, Error> {
    cases.iter().try_fold(0_u64, |total, case| {
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
        .built_indices
        .iter()
        .map(|index| {
            prepared.cases[*index]
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
            prepared.maximum_wire_bytes,
            prepared.requires_live_opt_in,
        )?;
    }
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
    fn execute<E, C>(
        mut self,
        built_indices: Vec<usize>,
        executor: &mut E,
        clock: &mut C,
    ) -> std::result::Result<Result, Error>
    where
        E: Executor,
        C: Clock,
    {
        for (ordinal, case_index) in built_indices.into_iter().enumerate() {
            let sequence = self.cases[case_index].index;
            self.pace(ordinal, sequence, clock)?;
            self.deadline.check().map_err(duration_limit)?;
            self.execute_case(case_index, executor)?;
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
        case_index: usize,
        executor: &mut E,
    ) -> std::result::Result<(), Error>
    where
        E: Executor,
    {
        let case = &mut self.cases[case_index];
        let execution_case = ExecutionCase {
            permit: crate::evidence::ExecutionPermit::new(),
            packet: case.recipe.clone(),
        };
        self.deadline
            .start_accounting(Duration::ZERO)
            .map_err(duration_limit)?;
        let execution = executor
            .execute(&execution_case, self.live.timeout)
            .map_err(|source| Error::Execution {
                case_index: case.index,
                source,
            })?;
        if execution.permit != execution_case.permit {
            return Err(Error::InvalidEvidence {
                case_index: case.index,
                message: "executor returned evidence for a different execution permit".to_owned(),
            });
        }
        let expected_live_build = expected_live_build(
            self.request,
            case.recipe.clone(),
            &self.registry,
            &execution,
        )
        .map_err(|message| Error::InvalidEvidence {
            case_index: case.index,
            message,
        })?;
        if execution.sent.wire_bytes() != &expected_live_build.bytes {
            return Err(Error::InvalidEvidence {
                case_index: case.index,
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
            self.live.timeout,
            &self.deadline,
        )?;
        add_execution_stats(&mut self.stats, &execution.stats, case.index)?;
        let had_response = !execution.responses.is_empty();
        case.diagnostics = execution.sent.built().diagnostics.clone();
        case.decoded = dissect_built(
            &self.live_dissector,
            execution.sent.built(),
            self.request.limits,
            &mut case.diagnostics,
        );
        self.deadline.check().map_err(duration_limit)?;
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

    fn finish(mut self) -> std::result::Result<Result, Error> {
        self.stats.elapsed = self.stats.elapsed.checked_add(self.scheduled_delay).ok_or(
            Error::StatisticsOverflow {
                case_index: last_case_index(self.request),
            },
        )?;
        self.deadline.check().map_err(duration_limit)?;

        Ok(Result {
            seed: self.request.seed,
            first_case: self.request.first_case,
            cases: self.cases,
            diagnostics: self.diagnostics,
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
    let mut preliminary = build_packet(&builder, packet.clone(), context.clone(), request)?;
    let preliminary_len = preliminary.bytes.len();

    if stringify(materialize_link_fields(&mut packet, route))? {
        if patch_builtin_ethernet(registry, &mut preliminary, &packet) {
            stringify(require_fixed_width_link_materialization(
                preliminary_len,
                preliminary.bytes.len(),
            ))?;
            return Ok(preliminary);
        }
        let materialized = build_packet(&builder, packet, context, request)?;
        stringify(require_fixed_width_link_materialization(
            preliminary_len,
            materialized.bytes.len(),
        ))?;
        return Ok(materialized);
    }

    stringify(require_fixed_width_link_materialization(
        preliminary_len,
        preliminary.bytes.len(),
    ))?;
    Ok(preliminary)
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
