// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;

use crate::clock::Clock;
use crate::target::SelectedAddress;

use super::pacing::{Owed, settle};
use super::pipelined::add_stats;
use crate::probe::enforce_deadline;
use crate::scan::Error;
use crate::scan::Request;
use crate::scan::discovery::{self, Composer};
use crate::scan::error::probe_error;
use crate::scan::executor::Pipelined;

/// Marks `host` started and returns `None` when it has already expired.
fn start_host(
    controller: &mut Option<&mut crate::scan::adaptive::Controller>,
    target: &SelectedAddress,
    now: std::time::Instant,
) -> Result<Option<usize>, ()> {
    let host = controller.as_deref_mut().map(|c| c.host_index(target));
    if let (Some(c), Some(h)) = (controller.as_deref_mut(), host) {
        c.host_started(h, now);
    }
    if host_expired(controller, host, now) {
        return Err(());
    }
    Ok(host)
}

fn host_expired(
    controller: &mut Option<&mut crate::scan::adaptive::Controller>,
    host: Option<usize>,
    now: std::time::Instant,
) -> bool {
    if let (Some(c), Some(h)) = (controller.as_deref_mut(), host)
        && c.host_expired(h, now)
    {
        c.mark_incomplete(h);
        return true;
    }
    false
}

fn host_deadline(
    controller: &Option<&mut crate::scan::adaptive::Controller>,
    host: Option<usize>,
    deadline: &Deadline,
    now: std::time::Instant,
) -> Result<Option<Deadline>, Error> {
    match (controller, host) {
        (Some(c), Some(h)) => deadline
            .for_wait(c.host_remaining(h, now))
            .map(Some)
            .map_err(Error::from),
        _ => Ok(None),
    }
}

/// Resolves each target's link address in selection order. Each request is
/// paced like a probe, and a silent neighbor is asked again until the
/// request's attempts are spent.
///
/// Returns the targets a frame can still be sent to: a target whose own
/// resolution stayed silent accepts nothing, so later stages skip it.
#[allow(clippy::too_many_arguments)]
pub(super) fn discover_neighbors<E: Pipelined, C: Clock>(
    request: &Request,
    targets: &[SelectedAddress],
    executor: &mut E,
    clock: &mut C,
    deadline: &mut Deadline,
    composer: &mut Composer,
    stats: &mut crate::Stats,
    owed: &mut Owed,
    controller: Option<&mut crate::scan::adaptive::Controller>,
) -> Result<Vec<bool>, Error> {
    let mut sendable = vec![true; targets.len()];
    let mut controller = controller;
    for (index, target) in targets.iter().enumerate() {
        let Ok(host) = start_host(&mut controller, target, clock.now()) else {
            sendable[index] = false;
            continue;
        };
        let mut attempts = 0;
        let mut last: Option<discovery::Neighbor> = None;
        let neighbor = loop {
            if host_expired(&mut controller, host, clock.now()) {
                break last;
            }
            // A pause owed by an earlier request is waited out only before
            // another; a target answered without one leaves it owed.
            if requests_neighbor(executor, target, true, deadline)? {
                settle(request, clock, deadline, owed, stats)?;
            }
            enforce_deadline(probe_error, deadline)?;
            if host_expired(&mut controller, host, clock.now()) {
                break last;
            }
            let timeout = host.map_or(request.timeout, |h| {
                controller.as_deref().map_or(request.timeout, |c| {
                    request.timeout.min(c.host_remaining(h, clock.now()))
                })
            });
            let began = clock.now();
            let (neighbor, exchange) = match executor.resolve_neighbor(target, timeout, deadline) {
                Ok(resolved) => resolved,
                Err(source) => {
                    if host_expired(&mut controller, host, clock.now()) {
                        break last;
                    }
                    return Err(Error::Neighbor {
                        address: target.address,
                        source,
                    });
                }
            };
            // A resolver stopped by the deadline reports silence; the deadline
            // decides instead.
            enforce_deadline(probe_error, deadline)?;
            if neighbor.attempts > 1 {
                return Err(Error::InvalidEvidence {
                    sequence: 0,
                    message: format!(
                        "neighbor discovery of {} sent {} requests in one attempt",
                        target.address, neighbor.attempts
                    ),
                });
            }
            add_stats(stats, &exchange, 0)?;
            let sent = neighbor.attempts > 0;
            owed.owe(usize::from(sent), Some(began));
            attempts += neighbor.attempts;
            let silent = matches!(neighbor.outcome, discovery::NeighborOutcome::Silent);
            if silent && host_expired(&mut controller, host, clock.now()) {
                break last;
            }
            let neighbor = discovery::Neighbor {
                attempts,
                ..neighbor
            };
            if !silent || !sent || attempts >= request.attempts {
                break Some(neighbor);
            }
            last = Some(neighbor);
        };
        match neighbor {
            Some(neighbor) => {
                sendable[index] = !matches!(neighbor.outcome, discovery::NeighborOutcome::Silent);
                composer.neighbor(index, neighbor);
            }
            None => sendable[index] = false,
        }
    }
    Ok(sendable)
}

/// Whether resolving `target`'s neighbor would send a request.
pub(super) fn requests_neighbor<E: Pipelined>(
    executor: &mut E,
    target: &SelectedAddress,
    explicit: bool,
    deadline: &Deadline,
) -> Result<bool, Error> {
    executor
        .requests_neighbor(target, explicit, deadline)
        .map_err(|source| Error::Neighbor {
            address: target.address,
            source,
        })
}

pub(super) enum ReachOutcome {
    Resolved,
    Silent(BoundaryError),
    HostExpired,
}

/// Resolves `target`'s next hop before its stage arms any capture, so no
/// resolution's capture overlaps a probe's and each request joins `stats`.
/// Returns why the target is unreachable when its next hop stayed silent.
#[allow(clippy::too_many_arguments)]
pub(super) fn reach_next_hop<E: Pipelined, C: Clock>(
    request: &Request,
    executor: &mut E,
    clock: &mut C,
    deadline: &mut Deadline,
    target: &SelectedAddress,
    stats: &mut crate::Stats,
    owed: &mut Owed,
    sequence: u64,
    mut controller: Option<&mut crate::scan::adaptive::Controller>,
) -> Result<ReachOutcome, Error> {
    let Ok(host) = start_host(&mut controller, target, clock.now()) else {
        return Ok(ReachOutcome::HostExpired);
    };
    let scoped = host_deadline(&controller, host, deadline, clock.now())?;
    let needs_request =
        requests_neighbor(executor, target, false, scoped.as_ref().unwrap_or(deadline))?;
    if needs_request {
        settle(request, clock, deadline, owed, stats)?;
    }
    enforce_deadline(probe_error, deadline)?;
    if host_expired(&mut controller, host, clock.now()) {
        return Ok(ReachOutcome::HostExpired);
    }
    let began = clock.now();
    let scoped = host_deadline(&controller, host, deadline, began)?;
    let resolved = match executor.resolve_next_hop(target, scoped.as_ref().unwrap_or(deadline)) {
        Ok(resolved) => resolved,
        Err(source) => {
            if host_expired(&mut controller, host, clock.now()) {
                return Ok(ReachOutcome::HostExpired);
            }
            return Err(Error::Neighbor {
                address: target.address,
                source,
            });
        }
    };
    // A resolver stopped by the deadline reports silence; the deadline
    // decides instead.
    enforce_deadline(probe_error, deadline)?;
    add_stats(stats, &resolved.stats, sequence)?;
    // A request spends the rate like a probe, so it is spaced from the next
    // request or the stage's first probe.
    let requests = usize::try_from(resolved.stats.packets_attempted).unwrap_or(usize::MAX);
    owed.owe(requests, Some(began));
    Ok(match resolved.silence {
        Some(source) => {
            if host_expired(&mut controller, host, clock.now()) {
                return Ok(ReachOutcome::HostExpired);
            }
            ReachOutcome::Silent(source)
        }
        None => ReachOutcome::Resolved,
    })
}
