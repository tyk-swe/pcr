// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Individual TCP connection admission, completion, and evidence.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::tcp::{self, Provider, Stream as _};

use super::super::error::probe_error;
use super::super::{Error, Request, Stage};
use super::planning::StagePlan;
use super::{Outcome, ProbeEvidence, execution};
use crate::clock::Clock;
use crate::policy::{Authorizer, Operation, SocketOperation};
use crate::target::{ResolveTarget, approve_operation};

pub(super) struct Active<S> {
    pub(super) pending: tcp::PendingConnect<S>,
    pub(super) sequence: u64,
    pub(super) stage: Stage,
    pub(super) endpoint: SocketAddr,
    pub(super) scope: Option<crate::target::ResolvedZone>,
    pub(super) attempt: u32,
    pub(super) started: Instant,
    pub(super) scheduled_at: SystemTime,
    pub(super) timeout: Duration,
    pub(super) selection: Option<super::super::adaptive::Selection>,
}

/// `None` means every native connect admission is still held, for example by
/// a cancelled attempt whose provider call has not returned or a finished one
/// whose worker has not yet released it, so the caller retries this endpoint.
#[allow(clippy::too_many_arguments)]
pub(super) fn admit_next<Q, A>(
    request: &Request,
    stage: &StagePlan<'_>,
    next: usize,
    authorizer: &mut A,
    deadline: &Deadline,
    provider: &Arc<Q>,
    budget: &tcp::ConnectBudget,
    clock: &impl Clock,
) -> Result<Option<Active<Q::Stream>>, Error>
where
    Q: Provider + 'static,
    Q::Stream: 'static,
    A: Authorizer + ResolveTarget,
{
    let endpoints = stage.targets.len() * stage.ports.len();
    let (endpoint, scope) = stage.endpoint(next % endpoints);
    let attempt = (next / endpoints) as u32 + 1;
    let sequence = stage.first_sequence + next as u64;
    let final_endpoints = [endpoint];
    let operation = SocketOperation::new(&final_endpoints, *stage.limits)
        .map_err(|source| execution(sequence, source))?;
    approve_operation(
        authorizer,
        Operation::Socket(operation),
        deadline,
        probe_error,
    )?;
    let timeout = deadline.bounded_timeout(request.timeout)?;
    let admitted = clock.now();
    let scheduled_at = SystemTime::now();
    let pending = match budget.start(
        Arc::clone(provider),
        endpoint,
        &Deadline::new(timeout).with_cancellation(deadline.cancellation().cloned()),
    ) {
        Ok(pending) => pending,
        Err(tcp::Error::Capacity { .. }) => return Ok(None),
        Err(source) => return Err(execution(sequence, source)),
    };
    Ok(Some(Active {
        pending,
        sequence,
        stage: stage.stage,
        endpoint,
        scope,
        attempt,
        started: admitted,
        scheduled_at,
        timeout,
        selection: None,
    }))
}

pub(super) fn settle_active<S: tcp::Stream>(
    active: &mut Vec<Active<S>>,
    index: usize,
    now: Instant,
) -> Result<Option<(Active<S>, ProbeEvidence)>, Error> {
    let result = active[index]
        .pending
        .poll()
        .map_err(|source| execution(active[index].sequence, source))?;
    if let Some(result) = result {
        let entry = active.remove(index);
        let probe = finish_probe(&entry, result)?;
        return Ok(Some((entry, probe)));
    }
    if now.saturating_duration_since(active[index].started) < active[index].timeout {
        return Ok(None);
    }
    let mut entry = active.remove(index);
    let attempted = entry.pending.cancel();
    let probe = ProbeEvidence {
        sequence: entry.sequence,
        stage: entry.stage,
        endpoint: entry.endpoint,
        scope: entry.scope.clone(),
        attempt: entry.attempt,
        attempted,
        connect_succeeded: None,
        outcome: Outcome::DeadlineExpired,
        scheduled_at: entry.scheduled_at,
        finished_at: None,
        elapsed: now.saturating_duration_since(entry.started),
        local: None,
        error: None,
    };
    Ok(Some((entry, probe)))
}

pub(super) fn connect_outcome(probe: &ProbeEvidence) -> super::super::adaptive::Outcome {
    if !probe.attempted {
        return super::super::adaptive::Outcome::Omitted;
    }
    match probe.outcome {
        Outcome::Connected | Outcome::Refused => super::super::adaptive::Outcome::Reply {
            latency: probe.elapsed,
            responder: probe.endpoint.ip(),
            control: false,
        },
        Outcome::TimedOut | Outcome::DeadlineExpired => super::super::adaptive::Outcome::Silent,
        Outcome::Unreachable | Outcome::LocalError => super::super::adaptive::Outcome::Aborted,
    }
}

fn finish_probe<S: tcp::Stream>(
    entry: &Active<S>,
    result: tcp::ConnectOutcome<S>,
) -> Result<ProbeEvidence, Error> {
    // Settled attempts keep the worker's completion time; publishing earlier
    // events can delay observation without extending the socket's latency.
    let elapsed = result.elapsed;
    let mut probe = ProbeEvidence {
        sequence: entry.sequence,
        stage: entry.stage,
        endpoint: entry.endpoint,
        scope: entry.scope.clone(),
        attempt: entry.attempt,
        attempted: result.attempted,
        connect_succeeded: Some(result.result.is_ok()),
        outcome: Outcome::LocalError,
        scheduled_at: result.started_at,
        finished_at: Some(result.completed_at),
        elapsed,
        local: None,
        error: None,
    };
    match result.result {
        Ok(stream) => {
            match endpoint_query(entry.sequence, "peer", stream.peer_addr())? {
                Some(peer) if peer != entry.endpoint => {
                    return Err(Error::InvalidEvidence {
                        sequence: entry.sequence,
                        message: "TCP provider returned a different peer endpoint".to_owned(),
                    });
                }
                Some(_) => {
                    probe.local = endpoint_query(entry.sequence, "local", stream.local_addr())?;
                }
                None => {}
            }
            probe.outcome = Outcome::Connected;
            drop(stream);
        }
        Err(error) => {
            let source = socket_error(error);
            probe.outcome = match source.kind() {
                io::ErrorKind::ConnectionRefused => Outcome::Refused,
                io::ErrorKind::TimedOut => Outcome::TimedOut,
                io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => {
                    Outcome::Unreachable
                }
                _ => Outcome::LocalError,
            };
            probe.error = Some(Arc::new(source));
        }
    }
    if elapsed > entry.timeout {
        probe.outcome = Outcome::DeadlineExpired;
    }
    Ok(probe)
}

/// A peer that reset after the handshake leaves no endpoint to query, but the
/// completed connect is still evidence, so `NotConnected` yields `None`.
fn endpoint_query(
    sequence: u64,
    operation: &'static str,
    result: io::Result<SocketAddr>,
) -> Result<Option<SocketAddr>, Error> {
    match result {
        Ok(endpoint) => Ok(Some(endpoint)),
        Err(source) if source.kind() == io::ErrorKind::NotConnected => Ok(None),
        Err(source) => Err(execution(
            sequence,
            tcp::Error::Evidence { operation, source },
        )),
    }
}

fn socket_error(error: tcp::Error) -> io::Error {
    match error {
        tcp::Error::Socket(source) => source,
        error @ tcp::Error::DeadlineExceeded => io::Error::new(io::ErrorKind::TimedOut, error),
        error @ tcp::Error::Cancelled(_) => io::Error::new(io::ErrorKind::Interrupted, error),
        error => io::Error::other(error),
    }
}
