// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::{build::Builder, fuzz as packet_fuzz, registry::Registry};

use crate::clock::Clock;
use crate::execution::{Context, ExchangeExecutor, Executor, Grant, publisher, rate_delay};
use crate::policy::{Authorizer, DeclaredPackets, Operation, PermissiveLive, WireLimits};
use crate::preparation::exact_bytes;
use crate::providers::Providers;
use crate::{Client, Sink};

use super::SYNTHESIZED_ETHERNET_BYTES;
use super::error::{CaseErrors, Error, duration_limit};
use super::evidence::{Recorder, validate_execution};
use super::executor::{CaseEvidence, CaseStep};
use super::plan::worst_case_duration;
use super::{Event, Report, Request, Trial};

impl<P: Providers, K: Clock> Client<P, K> {
    /// Runs one live fuzz campaign.
    ///
    /// Every case is generated and built offline first, exactly as
    /// [`packetcraftr_core::fuzz::run`] would, and the whole campaign — its
    /// packet count, worst-case bytes, destination, and permissive-live
    /// position — is admitted once before any provider is consulted. Each
    /// built case then runs as one capture-ready exchange, paced by the
    /// client's clock, and must have sent exactly the bytes its route
    /// prepares. Each case is published to `sink` in case order on a worker
    /// admitted by the client's runtime, and the campaign waits for the
    /// sink's answer before it sends the next case. The campaign deadline
    /// bounds waiting for the sink, not the sink itself.
    ///
    /// # Errors
    ///
    /// Returns the invalid request or campaign, the refused admission, the
    /// executed case's failure or invalid evidence, the sink's failure, or
    /// the clock's failure.
    pub fn fuzz<S>(&self, request: Request, sink: S) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let mut deadline = self.deadline(request.campaign.limits.max_duration);
        let publish = publisher(&self.runtime, sink, duration_limit, |source| {
            Error::Output { source }
        })?;
        let mut executor = ExchangeExecutor::new(self, request.send(), request.collection.clone());
        run(
            &request,
            &mut self.admission(),
            Arc::clone(&self.registry),
            &mut executor,
            &mut self.clock.clone(),
            &mut deadline,
            publish,
        )
    }
}

/// Builds and validates all cases offline, admits the campaign, then
/// executes it and publishes cases in deterministic case order as soon as
/// each live outcome is final.
pub(super) fn run<A, E, C, F>(
    request: &Request,
    authorizer: &mut A,
    registry: Arc<Registry>,
    executor: &mut E,
    clock: &mut C,
    deadline: &mut Deadline,
    mut emit: F,
) -> Result<Report, Error>
where
    A: Authorizer,
    E: Executor<CaseStep>,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    deadline.check_cancelled()?;
    request.validate()?;
    let prepared = prepare_campaign(request, &registry, deadline)?;
    deadline.enforce()?;
    authorize_campaign(request, &prepared, authorizer)?;
    deadline.enforce()?;

    let PreparedCampaign {
        cases,
        stats: campaign,
        ..
    } = prepared;
    let delay = rate_delay(&CaseErrors, "cases_per_second", 1, request.cases_per_second)?;
    let builder = Builder::new(Arc::clone(&registry));
    let mut recorder = Recorder::new(registry, request.campaign.limits, request.evidence());
    let mut context = Context::new(deadline, clock, CaseErrors);
    let mut executed_before = false;
    for mut case in cases {
        let case_index = case.index;
        context.enforce(case_index)?;
        let mut evidence = None;
        if case.built.is_some() {
            // Cases per second: every built case after the first waits one
            // case's share of a second.
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
                |_, execution, grant, deadline| {
                    validate_case(request, &builder, &case, execution, grant, deadline)
                },
            )?;
            evidence = Some(recorder.record(&mut case, execution, context.deadline())?);
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
    let worst_case = worst_case_duration(request, built_cases)?;
    deadline
        .check_additional(worst_case)
        .map_err(duration_limit)?;
    let maximum_wire_bytes = maximum_wire_bytes(&request.campaign, &cases)?;
    // Whether the opt-in is *needed* is decided here; whether it was *given*
    // is decided later by the authorizer that `authorize_campaign` calls, so
    // `policy.allow_permissive_packets` also applies.
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

/// Admits the declared campaign through the client's one admission path.
/// Fuzz deliberately stays outside `target::admit_operation`: there is no
/// declared target to resolve, and the caller's cancellation-aware `enforce`
/// brackets let a refusal outrank a deadline spent during the call —
/// `approve_operation`'s elapsed-only gate would report the deadline first.
fn authorize_campaign<A>(
    request: &Request,
    prepared: &PreparedCampaign,
    authorizer: &mut A,
) -> Result<(), Error>
where
    A: Authorizer,
{
    let packets = prepared
        .cases
        .iter()
        .filter_map(|case| case.built.as_ref().map(|built| &built.packet))
        .collect::<Vec<_>>();
    // Unconditional: a campaign with no buildable case still has to clear
    // policy validation and the destination gate before anything else runs.
    let permissive_live = if prepared.requires_permissive_live {
        PermissiveLive::Required {
            allowed: request.allow_permissive_live,
        }
    } else {
        PermissiveLive::NotRequired
    };
    authorizer.authorize_operation(Operation::Declared(DeclaredPackets::new(
        WireLimits::new(prepared.stats.cases_built, prepared.maximum_wire_bytes),
        &packets,
        request.destination,
        permissive_live,
    )))?;
    Ok(())
}

/// Judges one case's evidence before any of it is recorded: the executor must
/// have sent exactly the route-materialized authorized case, within the
/// campaign's packet limit, and every response must arrive within the
/// granted, already clipped, timeout.
fn validate_case(
    request: &Request,
    builder: &Builder,
    case: &packet_fuzz::Case,
    execution: &CaseEvidence,
    grant: Grant,
    deadline: &Deadline,
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
        deadline,
    )
}

fn last_case_index(request: &packet_fuzz::Request) -> u64 {
    request
        .first_case
        .saturating_add(u64::try_from(request.cases.saturating_sub(1)).unwrap_or(u64::MAX))
}
