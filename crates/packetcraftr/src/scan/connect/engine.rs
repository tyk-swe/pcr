// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::tcp::{self, Provider, Stream as _};

use crate::deadline::DeadlineExt as _;
use crate::providers::{TargetProviders, TcpOf, TcpProviders};
use crate::{
    Client, Sink,
    clock::Clock,
    execution::rate_delay,
    policy::{Authorizer, Operation, SocketLimits, SocketOperation},
    probe::{Transport, enforce_deadline},
    target::ResolveTarget,
    target::{DeclaredTargets, FamilyGate, admit_selection, approve_operation},
};
use packetcraftr_core::error::BoundaryError;

use super::super::error::Probes;
use super::super::plan::{probe_count, worst_case_duration};
use super::super::report::RttAccumulator;
use super::super::{Error, Request};
use super::{Event, Outcome, ProbeEvidence, Report, Stats};

impl<P: TargetProviders + TcpProviders, K: Clock> Client<P, K> {
    /// Scans the request's targets and ports with kernel TCP connects
    /// through the client's TCP provider, keeping at most `max_in_flight`
    /// attempts pending at once.
    pub fn scan_connect<S>(&self, request: Request, sink: S) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let started = self.now();
        let mut deadline = self.deadline(request.limits.max_duration);
        let mut publish =
            crate::execution::publisher(&self.runtime, sink, Error::from, |source| {
                Error::Output { source }
            })?;
        run(
            &request,
            &mut self.admission(),
            &Arc::new(TcpOf(Arc::clone(&self.providers))),
            &self.clock,
            &mut deadline,
            started,
            |probe, deadline| publish(Event::Probe(probe), deadline),
        )
    }
}

struct Active<S> {
    pending: tcp::PendingConnect<S>,
    sequence: u64,
    endpoint: SocketAddr,
    attempt: u32,
    started: Instant,
    scheduled_at: SystemTime,
    timeout: Duration,
}
fn invalid(field: &'static str, value: usize, reason: &str) -> Error {
    Error::InvalidLimit {
        field,
        value: value as u64,
        reason: reason.to_owned(),
    }
}
fn execution(
    sequence: u64,
    source: impl packetcraftr_core::error::Classified + Send + Sync + 'static,
) -> Error {
    Error::Execution {
        sequence,
        source: BoundaryError::from_error(source),
    }
}

struct Planned {
    endpoints: Vec<SocketAddr>,
    count: usize,
    delay: Duration,
    limits: SocketLimits,
    planned_duration: Duration,
}

fn planned<A: Authorizer + ResolveTarget>(
    request: &Request,
    authorizer: &mut A,
    deadline: &Deadline,
) -> Result<(Vec<IpAddr>, Planned), Error> {
    request.validate()?;
    if request.transport != Transport::Tcp {
        return Err(invalid(
            "transport",
            0,
            "TCP connect requires TCP transport",
        ));
    }
    if request.route.requires_packet_route() {
        return Err(Error::UnsupportedTcpRoute);
    }
    if request.max_in_flight > tcp::MAX_PENDING_CONNECTIONS {
        return Err(invalid(
            "max_in_flight",
            request.max_in_flight,
            "TCP connect is capped at 16 concurrent native operations",
        ));
    }
    let ports = request.selected_ports()?;
    if ports.contains(&0) {
        return Err(invalid("port", 0, "TCP connect requires nonzero ports"));
    }
    let (selected, planned) = admit_selection(
        authorizer,
        deadline,
        &Probes,
        DeclaredTargets {
            selection: &request.targets,
            family: FamilyGate::new(request.address_family, Error::family),
            max_targets: request.limits.max_targets,
        },
        Error::TargetSelection,
        |selected| {
            let count = probe_count(selected.addresses.len(), ports.len(), request.attempts)?;
            crate::probe::check_probe_count(&Probes, count, request.limits.max_probes)?;
            let delay = rate_delay(&Probes, "probes_per_second", 1, request.probes_per_second)?;
            let planned_duration = worst_case_duration(request, count)?;
            crate::probe::check_probe_duration(
                &Probes,
                planned_duration,
                request.limits.max_duration,
            )?;
            let endpoints = selected
                .addresses
                .iter()
                .flat_map(|address| {
                    ports
                        .iter()
                        .map(move |port| SocketAddr::new(*address, *port))
                })
                .collect();
            Ok(Planned {
                endpoints,
                count,
                delay,
                limits: SocketLimits::new(count as u64, 0, 0),
                planned_duration,
            })
        },
        |planned| {
            SocketOperation::new(&planned.endpoints, planned.limits)
                .map(Operation::Socket)
                .map_err(|source| execution(0, source))
        },
    )?;
    Ok((selected.addresses, planned))
}

/// `None` means every native connect admission is still held, for example by
/// a cancelled attempt whose provider call has not returned or a finished one
/// whose worker has not yet released it, so the caller retries this endpoint.
fn admit_next<Q, A>(
    request: &Request,
    planned: &Planned,
    next: usize,
    authorizer: &mut A,
    deadline: &Deadline,
    provider: &Arc<Q>,
    clock: &impl Clock,
) -> Result<Option<Active<Q::Stream>>, Error>
where
    Q: Provider + 'static,
    Q::Stream: 'static,
    A: Authorizer + ResolveTarget,
{
    let endpoint = planned.endpoints[next % planned.endpoints.len()];
    let attempt = (next / planned.endpoints.len()) as u32 + 1;
    let final_endpoints = [endpoint];
    let operation = SocketOperation::new(&final_endpoints, planned.limits)
        .map_err(|source| execution(next as u64, source))?;
    approve_operation(authorizer, Operation::Socket(operation), deadline, &Probes)?;
    let timeout = deadline.bounded_timeout(request.timeout)?;
    let admitted = clock.now();
    let scheduled_at = SystemTime::now();
    let pending = match tcp::start_connect(
        Arc::clone(provider),
        endpoint,
        &Deadline::new(timeout).with_cancellation(deadline.cancellation().cloned()),
    ) {
        Ok(pending) => pending,
        Err(tcp::Error::Capacity { .. }) => return Ok(None),
        Err(source) => return Err(execution(next as u64, source)),
    };
    Ok(Some(Active {
        pending,
        sequence: next as u64,
        endpoint,
        attempt,
        started: admitted,
        scheduled_at,
        timeout,
    }))
}

fn settle_active<S: tcp::Stream>(
    active: &mut Vec<Active<S>>,
    index: usize,
    now: Instant,
) -> Result<Option<ProbeEvidence>, Error> {
    let result = active[index]
        .pending
        .poll()
        .map_err(|source| execution(active[index].sequence, source))?;
    if let Some(result) = result {
        let entry = active.remove(index);
        return Ok(Some(finish_probe(entry, result)?));
    }
    if now.saturating_duration_since(active[index].started) < active[index].timeout {
        return Ok(None);
    }
    let mut entry = active.remove(index);
    let attempted = entry.pending.cancel();
    Ok(Some(ProbeEvidence {
        sequence: entry.sequence,
        endpoint: entry.endpoint,
        attempt: entry.attempt,
        attempted,
        connect_succeeded: None,
        outcome: Outcome::DeadlineExpired,
        scheduled_at: entry.scheduled_at,
        finished_at: None,
        elapsed: now.saturating_duration_since(entry.started),
        local: None,
        error: None,
    }))
}

fn run<Q, A, C, F>(
    request: &Request,
    authorizer: &mut A,
    provider: &Arc<Q>,
    clock: &C,
    deadline: &mut Deadline,
    started: Instant,
    mut emit: F,
) -> Result<Report, Error>
where
    Q: Provider + 'static,
    Q::Stream: 'static,
    A: Authorizer + ResolveTarget,
    C: Clock,
    F: FnMut(ProbeEvidence, &Deadline) -> Result<(), Error>,
{
    enforce_deadline(&Probes, deadline)?;
    let (resolved_addresses, planned) = planned(request, authorizer, deadline)?;
    let mut stats = Stats::default();
    let mut rtt = RttAccumulator::default();
    let mut active: Vec<Active<Q::Stream>> = Vec::new();
    let mut next = 0usize;
    let mut next_start = clock.now();
    let mut evidence_bytes = 0usize;
    while next < planned.count || !active.is_empty() {
        enforce_deadline(&Probes, deadline)?;
        let mut admission_held = false;
        while next < planned.count
            && active.len() < request.max_in_flight
            && clock.now() >= next_start
        {
            let Some(admitted) = admit_next(
                request, &planned, next, authorizer, deadline, provider, clock,
            )?
            else {
                admission_held = true;
                break;
            };
            active.push(admitted);
            stats.connections_scheduled += 1;
            next += 1;
            next_start = clock
                .now()
                .checked_add(planned.delay)
                .ok_or_else(|| invalid("rate", 0, "pacing deadline overflow"))?;
        }
        let mut index = 0;
        while index < active.len() {
            enforce_deadline(&Probes, deadline)?;
            let Some(probe) = settle_active(&mut active, index, clock.now())? else {
                index += 1;
                continue;
            };
            evidence_bytes = evidence_bytes
                .checked_add(std::mem::size_of::<ProbeEvidence>())
                .and_then(|bytes| {
                    bytes.checked_add(
                        probe
                            .error
                            .as_ref()
                            .map_or(0, |error| error.to_string().len()),
                    )
                })
                .filter(|bytes| *bytes <= request.limits.max_evidence_bytes)
                .ok_or_else(|| {
                    invalid(
                        "max_evidence_bytes",
                        request.limits.max_evidence_bytes,
                        "socket evidence budget exceeded",
                    )
                })?;
            stats.connections_attempted += u64::from(probe.attempted);
            stats.connections_succeeded += u64::from(probe.connect_succeeded == Some(true));
            if probe.attempted {
                rtt.note_sent();
            }
            if matches!(
                probe.outcome,
                Outcome::Connected | Outcome::Refused | Outcome::Unreachable
            ) {
                rtt.note_received(probe.elapsed);
            }
            emit(probe, deadline)?;
        }
        if next < planned.count || !active.is_empty() {
            let mut wait = Duration::from_millis(1);
            if next < planned.count && active.len() < request.max_in_flight && !admission_held {
                wait = wait.min(next_start.saturating_duration_since(clock.now()));
            }
            if !wait.is_zero() {
                deadline.start_accounting(Duration::ZERO)?;
                clock.sleep(wait, deadline).map_err(|source| Error::Clock {
                    sequence: next as u64,
                    source: Box::new(source),
                })?;
            }
        }
    }
    enforce_deadline(&Probes, deadline)?;
    stats.elapsed = clock.now().saturating_duration_since(started);
    stats.rtt = rtt.finish();
    Ok(Report {
        target: request.targets.to_string(),
        resolved_addresses,
        planned_duration: planned.planned_duration,
        stats,
    })
}

fn finish_probe<S: tcp::Stream>(
    entry: Active<S>,
    result: tcp::ConnectOutcome<S>,
) -> Result<ProbeEvidence, Error> {
    // Settled attempts keep the worker's completion time; publishing earlier
    // events can delay observation without extending the socket's latency.
    let elapsed = result.elapsed;
    let mut probe = ProbeEvidence {
        sequence: entry.sequence,
        endpoint: entry.endpoint,
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
