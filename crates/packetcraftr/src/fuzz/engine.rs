// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::{build::Builder, fuzz as packet_fuzz, registry::Registry};

use crate::clock::Clock;
use crate::engine::execution::{Context, Executor, Grant, publisher, rate_delay};
use crate::engine::operation::{Workflow, WorkflowSetup};
use crate::engine::preparation::exact_bytes;
use crate::exchange::WorkflowExecutor;
use crate::policy::{Authorizer, DeclaredPackets, Operation, PermissiveLive, WireLimits};
use crate::providers::PacketProviders;
use crate::{Client, Sink};

use super::SYNTHESIZED_ETHERNET_BYTES;
use super::error::{Error, duration_limit};
use super::evidence::{Recorder, validate_execution};
use super::executor::{CaseEvidence, CaseStep};
use super::plan::worst_case_duration;
use super::{Event, Report, Request, Trial};

#[cfg(test)]
mod tests;

impl<P: PacketProviders, K: Clock> Client<P, K> {
    pub fn fuzz<S>(&self, request: Request, sink: S) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let operation =
            crate::engine::operation::Operation::new(self, request.campaign.limits.max_duration);
        self.policy
            .authorize_window_at(operation.admitted_at)
            .map_err(|source| {
                Error::Authorization(packetcraftr_core::error::BoundaryError::from_error(source))
            })?;
        let setup = WorkflowSetup::with_authorizer(self, &operation, self.policy.as_ref());
        let mut workflow = setup.start(self, request.campaign.limits.max_duration);
        let publish = publisher(&self.runtime, sink, duration_limit, |source| {
            Error::Output { source }
        })?;
        let mut executor =
            WorkflowExecutor::new(self, &operation, request.send(), request.collection.clone());
        run(&request, &mut workflow, &mut executor, publish)
    }
}

fn execute_baseline<E, C>(
    context: &mut Context<'_, C, Error>,
    executor: &mut E,
    request: &Request,
    builder: &Builder,
    reference_case: &packet_fuzz::Case,
    executed_before: &mut bool,
    delay: std::time::Duration,
) -> Result<bool, Error>
where
    E: Executor<CaseStep>,
    C: Clock,
{
    if *executed_before {
        context.pace(reference_case.index, delay)?;
    }
    *executed_before = true;
    let mut baseline_case = reference_case.clone();
    baseline_case.recipe = request.packet.clone();
    let (execution, _) = context.step(
        reference_case.index,
        request.timeout,
        executor,
        |executor, grant| {
            executor.execute(&CaseStep {
                permit: grant.permit,
                packet: request.packet.clone(),
                timeout: grant.timeout,
            })
        },
        |_, execution, grant, _| validate_case(request, builder, &baseline_case, execution, grant),
    )?;
    Ok(!execution.responses.is_empty())
}

fn liveness_timeout() -> packetcraftr_core::diagnostic::Diagnostic {
    packetcraftr_core::diagnostic::Diagnostic::new(
        packetcraftr_core::diagnostic::Severity::Warning,
        "fuzz.liveness_timeout",
        "baseline exchange timed out; later case outcomes are inconclusive",
    )
}

pub(super) fn run<A, E, C, F>(
    request: &Request,
    workflow: &mut Workflow<A, C>,
    executor: &mut E,
    mut emit: F,
) -> Result<Report, Error>
where
    A: Authorizer,
    E: Executor<CaseStep>,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    let Workflow {
        authorizer,
        registry,
        clock,
        deadline,
    } = workflow;
    deadline.check_cancelled()?;
    request.validate()?;
    let prepared = prepare_campaign(request, registry, deadline)?;
    deadline.enforce()?;
    authorize_campaign(request, &prepared, authorizer)?;
    deadline.enforce()?;

    let PreparedCampaign {
        cases,
        stats: campaign,
        ..
    } = prepared;
    let delay = rate_delay::<Error>("cases_per_second", 1, request.cases_per_second)?;
    let builder = Builder::new(Arc::clone(registry));
    let mut recorder = Recorder::new(
        Arc::clone(registry),
        request.campaign.limits,
        request.evidence(),
    );
    let mut context = Context::new(deadline, clock);
    let mut executed_before = false;
    let mut target_alive = true;
    if request.liveness
        && let Some(reference) = cases.iter().find(|case| case.built.is_some()).cloned()
    {
        target_alive = execute_baseline(
            &mut context,
            executor,
            request,
            &builder,
            &reference,
            &mut executed_before,
            delay,
        )?;
    }
    for mut case in cases {
        let case_index = case.index;
        context.enforce(case_index)?;
        if !target_alive {
            case.diagnostics.push(liveness_timeout());
            recorder.publish_diagnostics(&mut case)?;
            emit(
                Event::Case(Trial {
                    case,
                    evidence: None,
                }),
                context.deadline(),
            )?;
            continue;
        }
        let mut evidence = None;
        if case.built.is_some() {
            if executed_before {
                context.pace(case_index, delay)?;
            }
            executed_before = true;
            let (execution, _) = context.step(
                case_index,
                request.timeout,
                &mut *executor,
                |executor, grant| {
                    executor.execute(&CaseStep {
                        permit: grant.permit,
                        packet: case.recipe.clone(),
                        timeout: grant.timeout,
                    })
                },
                |_, execution, grant, _| validate_case(request, &builder, &case, execution, grant),
            )?;
            evidence = Some(recorder.record(&mut case, execution, context.deadline())?);
            if request.liveness {
                target_alive = execute_baseline(
                    &mut context,
                    executor,
                    request,
                    &builder,
                    &case.clone(),
                    &mut executed_before,
                    delay,
                )?;
                if !target_alive {
                    case.diagnostics.push(liveness_timeout());
                }
            }
        }
        recorder.publish_diagnostics(&mut case)?;
        emit(Event::Case(Trial { case, evidence }), context.deadline())?;
    }
    context.enforce(last_case_index(&request.campaign))?;

    Ok(Report {
        seed: request.campaign.seed,
        first_case: request.campaign.first_case,
        campaign,
        stats: context.into_stats(),
    })
}

struct PreparedCampaign {
    cases: Vec<packet_fuzz::Case>,
    stats: packet_fuzz::Stats,
    maximum_wire_bytes: u64,
    requires_permissive_live: bool,
    liveness_steps: usize,
}

fn prepare_campaign(
    request: &Request,
    registry: &Arc<Registry>,
    deadline: &mut Deadline,
) -> Result<PreparedCampaign, Error> {
    let campaign = packet_fuzz::Campaign::prepare(
        &request.campaign,
        request.packet.clone(),
        Arc::clone(registry),
        deadline,
    )?;
    let stats = campaign.stats().clone();
    let cases = campaign.into_cases();
    let built_cases = cases.iter().filter(|case| case.built.is_some()).count();

    deadline.enforce()?;
    let liveness_steps = if request.liveness && built_cases > 0 {
        built_cases + 1
    } else {
        0
    };
    let worst_case = worst_case_duration(request, built_cases + liveness_steps)?;
    deadline
        .check_additional(worst_case)
        .map_err(duration_limit)?;
    let mut maximum_wire_bytes = maximum_wire_bytes(&request.campaign, &cases)?;
    if liveness_steps > 0 {
        let overhead = match packet_fuzz::packet_link_type(&request.packet) {
            Some(link_type) if !link_type.is_raw_ip() => 0,
            _ => super::SYNTHESIZED_ETHERNET_BYTES,
        };
        let per_step = (request.campaign.limits.max_packet_bytes as u64)
            .checked_add(overhead)
            .ok_or(Error::StatisticsOverflow {
                case_index: last_case_index(&request.campaign),
            })?;
        let baseline_bytes =
            per_step
                .checked_mul(liveness_steps as u64)
                .ok_or(Error::StatisticsOverflow {
                    case_index: last_case_index(&request.campaign),
                })?;
        maximum_wire_bytes =
            maximum_wire_bytes
                .checked_add(baseline_bytes)
                .ok_or(Error::StatisticsOverflow {
                    case_index: last_case_index(&request.campaign),
                })?;
    }
    // Whether the opt-in is *needed* is decided here; whether it was *given*
    // is decided later by the authorizer that `authorize_campaign` calls.
    let requires_permissive_live = cases.iter().any(|case| {
        case.built
            .as_ref()
            .is_some_and(crate::policy::requires_live_opt_in)
    });

    Ok(PreparedCampaign {
        cases,
        stats,
        maximum_wire_bytes,
        requires_permissive_live,
        liveness_steps,
    })
}

fn maximum_wire_bytes(
    request: &packet_fuzz::Request,
    cases: &[packet_fuzz::Case],
) -> Result<u64, Error> {
    cases.iter().try_fold(0_u64, |total, case| {
        let Some(built) = &case.built else {
            return Ok(total);
        };
        let overhead = match packet_fuzz::packet_link_type(&built.packet) {
            Some(link_type) if !link_type.is_raw_ip() => 0,
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
    request: &Request,
    prepared: &PreparedCampaign,
    authorizer: &mut A,
) -> Result<(), Error>
where
    A: Authorizer,
{
    let mut packets = prepared
        .cases
        .iter()
        .filter_map(|case| case.built.as_ref().map(|built| &built.packet))
        .collect::<Vec<_>>();
    if prepared.liveness_steps > 0 {
        packets.push(&request.packet);
    }
    // Unconditional: a campaign with no buildable case still has to clear
    // policy validation and the destination gate before anything else runs.
    let permissive_live = if prepared.requires_permissive_live {
        PermissiveLive::Required {
            allowed: request.allow_permissive_live,
        }
    } else {
        PermissiveLive::NotRequired
    };
    authorizer
        .authorize_operation(Operation::Declared(DeclaredPackets::new(
            WireLimits::new(
                prepared.stats.cases_built + prepared.liveness_steps as u64,
                prepared.maximum_wire_bytes,
            ),
            &packets,
            request.destination,
            permissive_live,
        )))
        .map_err(Error::Authorization)
}

fn validate_case(
    request: &Request,
    builder: &Builder,
    case: &packet_fuzz::Case,
    execution: &CaseEvidence,
    grant: Grant,
) -> Result<(), Error> {
    let route = execution.sent.route();
    let expected = exact_bytes(builder, &request.campaign.build, case.recipe.clone(), route)
        .map_err(|source| Error::UnverifiableRoute {
            case_index: case.index,
            source,
        })?;
    if execution.sent.wire_bytes() != &expected {
        return Err(Error::InvalidEvidence {
            case_index: case.index,
            message: "executor substituted bytes for the route-materialized case".to_owned(),
        });
    }
    validate_execution(
        case,
        execution,
        grant.timeout,
        request.campaign.limits.max_packet_bytes,
    )
}

fn last_case_index(request: &packet_fuzz::Request) -> u64 {
    request
        .first_case
        .saturating_add(u64::try_from(request.cases.saturating_sub(1)).unwrap_or(u64::MAX))
}
