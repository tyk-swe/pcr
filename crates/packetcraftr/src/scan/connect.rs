// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Explicit kernel TCP scanning with socket evidence and bounded rolling admission.

use super::error::Probes;
use super::{Classification, Error, Request};
use crate::deadline::DeadlineExt as _;
use crate::{
    BoundaryError,
    clock::Clock,
    policy::{Authorizer, Operation, SocketLimits, SocketOperation},
    probe::{Transport, enforce_deadline},
    target::{DeclaredTargets, FamilyGate, admit_selection, approve_operation},
};
use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::tcp::{self, Provider, Stream as _};
use serde::Serialize;
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Connected,
    Refused,
    TimedOut,
    Unreachable,
    LocalError,
    DeadlineExpired,
}
impl Outcome {
    pub const fn classification(self) -> Classification {
        match self {
            Self::Connected => Classification::Open,
            Self::Refused => Classification::Closed,
            Self::TimedOut | Self::DeadlineExpired => Classification::Timeout,
            Self::Unreachable => Classification::Unreachable,
            Self::LocalError => Classification::Unknown,
        }
    }
}
#[derive(Clone, Debug)]
pub struct Probe {
    pub sequence: u64,
    pub endpoint: SocketAddr,
    pub attempt: u32,
    pub attempted: bool,
    /// None means no socket-call result was available by the deadline.
    pub connect_succeeded: Option<bool>,
    pub outcome: Outcome,
    pub scheduled_at: SystemTime,
    pub finished_at: Option<SystemTime>,
    pub elapsed: Duration,
    pub local: Option<SocketAddr>,
    pub error: Option<Arc<io::Error>>,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct Stats {
    pub connections_scheduled: u64,
    pub connections_attempted: u64,
    pub connections_succeeded: u64,
    pub elapsed: Duration,
    /// Round-trip accounting across the admitted connect attempts: a probe
    /// counts as sent once the kernel accepted its connect call, and as
    /// received when it finished with a connected, refused, or unreachable
    /// verdict before its deadline. Timed-out, deadline-expired, and
    /// local-error attempts count as lost and contribute no sample.
    pub rtt: super::Rtt,
}
#[derive(Clone, Debug)]
pub struct Summary {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub planned_duration: Duration,
    pub stats: Stats,
}
#[derive(Clone, Debug)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
    pub classification: Classification,
    pub probes: Vec<Probe>,
}
#[derive(Clone, Debug)]
pub struct Report {
    pub summary: Summary,
    pub endpoints: Vec<Endpoint>,
}

pub fn run<P, A, C>(
    request: &Request,
    authorizer: &mut A,
    provider: Arc<P>,
    clock: &mut C,
) -> Result<Report, Error>
where
    P: Provider + 'static,
    P::Stream: 'static,
    A: Authorizer,
    C: Clock,
{
    let mut probes = Vec::new();
    let summary = run_observed(request, authorizer, provider, clock, |probe, _| {
        probes.push(probe);
        Ok(())
    })?;
    probes.sort_by_key(|probe| probe.sequence);
    let mut endpoints: Vec<Endpoint> = Vec::new();
    let mut indices = HashMap::new();
    for probe in probes {
        let key = probe.endpoint;
        let index = *indices.entry(key).or_insert_with(|| {
            let index = endpoints.len();
            endpoints.push(Endpoint {
                address: key.ip(),
                port: key.port(),
                classification: Classification::Timeout,
                probes: Vec::new(),
            });
            index
        });
        endpoints[index]
            .classification
            .promote(probe.outcome.classification());
        endpoints[index].probes.push(probe);
    }
    Ok(Report { summary, endpoints })
}

pub fn run_with_events<P, A, C, F>(
    request: &Request,
    authorizer: &mut A,
    provider: Arc<P>,
    clock: &mut C,
    runtime: &crate::progress::Runtime,
    emit: F,
) -> Result<Summary, Error>
where
    P: Provider + 'static,
    P::Stream: 'static,
    A: Authorizer,
    C: Clock,
    F: FnMut(Probe) -> Result<(), BoundaryError> + Send + 'static,
{
    let observe = crate::execution::sink_observer(
        runtime,
        emit,
        |error| Error::DurationLimit {
            actual: error.actual,
            limit: error.limit,
        },
        |source| Error::Output { source },
    )?;
    run_observed(request, authorizer, provider, clock, observe)
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

/// The authorized connect plan: every endpoint to probe, the total attempt
/// count, the pacing delay, and the approved socket limits. The admitted
/// addresses accompany the plan in the return value for the summary.
struct Planned {
    endpoints: Vec<SocketAddr>,
    count: usize,
    delay: Duration,
    limits: SocketLimits,
    planned_duration: Duration,
}

/// Validates the connect-specific request, admits the declared targets, and
/// approves the complete socket limits before any connection is scheduled.
fn planned<A: Authorizer>(
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
            let count = selected
                .addresses
                .len()
                .checked_mul(ports.len())
                .and_then(|count| count.checked_mul(request.attempts as usize))
                .ok_or_else(|| invalid("probes", usize::MAX, "probe count overflow"))?;
            crate::probe::check_probe_count(&Probes, count, request.limits.max_probes)?;
            let delay = crate::clock::rate_delay(1, request.probes_per_second)
                .ok_or_else(|| invalid("rate", 0, "invalid rate"))?;
            let windows = u32::try_from(count.div_ceil(request.max_in_flight))
                .map_err(|_| invalid("probes", count, "duration overflow"))?;
            let planned_duration = request
                .timeout
                .checked_mul(windows)
                .and_then(|duration| {
                    delay
                        .checked_mul(count.saturating_sub(1) as u32)
                        .and_then(|pacing| duration.checked_add(pacing))
                })
                .ok_or_else(|| invalid("duration", count, "duration overflow"))?;
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

/// Approves and starts one connection attempt, returning the pending socket.
/// `None` means every native connect admission is still held, for example by
/// a cancelled attempt whose provider call has not returned or a finished one
/// whose worker has not yet released it, so the caller retries this endpoint.
fn admit_next<P, A, C>(
    request: &Request,
    planned: &Planned,
    next: usize,
    authorizer: &mut A,
    deadline: &Deadline,
    provider: &Arc<P>,
    clock: &mut C,
) -> Result<Option<Active<P::Stream>>, Error>
where
    P: Provider + 'static,
    P::Stream: 'static,
    A: Authorizer,
    C: Clock,
{
    let endpoint = planned.endpoints[next % planned.endpoints.len()];
    let attempt = (next / planned.endpoints.len()) as u32 + 1;
    let final_endpoints = [endpoint];
    let operation = SocketOperation::new(&final_endpoints, planned.limits)
        .map_err(|source| execution(next as u64, source))?;
    approve_operation(authorizer, Operation::Socket(operation), deadline, &Probes)?;
    let timeout = deadline
        .bounded_timeout(request.timeout)
        .map_err(|source| Error::DurationLimit {
            actual: source.actual,
            limit: source.limit,
        })?;
    let admitted = Instant::now();
    let scheduled_at = SystemTime::now();
    let pending = match tcp::start_connect(
        Arc::clone(provider),
        endpoint,
        &Deadline::new(timeout).with_cancellation(clock.cancellation()),
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

/// Polls one pending connection, removing and settling it when it finished or
/// exceeded its deadline. `None` means it is still pending.
fn settle_active<S: tcp::Stream>(
    active: &mut Vec<Active<S>>,
    index: usize,
) -> Result<Option<Probe>, Error> {
    let result = active[index]
        .pending
        .poll()
        .map_err(|source| execution(active[index].sequence, source))?;
    if let Some(result) = result {
        let entry = active.remove(index);
        return Ok(Some(finish_probe(entry, result)?));
    }
    if active[index].started.elapsed() < active[index].timeout {
        return Ok(None);
    }
    let mut entry = active.remove(index);
    let attempted = entry.pending.cancel();
    Ok(Some(Probe {
        sequence: entry.sequence,
        endpoint: entry.endpoint,
        attempt: entry.attempt,
        attempted,
        connect_succeeded: None,
        outcome: Outcome::DeadlineExpired,
        scheduled_at: entry.scheduled_at,
        finished_at: None,
        elapsed: entry.started.elapsed(),
        local: None,
        error: None,
    }))
}

fn run_observed<P, A, C, F>(
    request: &Request,
    authorizer: &mut A,
    provider: Arc<P>,
    clock: &mut C,
    mut emit: F,
) -> Result<Summary, Error>
where
    P: Provider + 'static,
    P::Stream: 'static,
    A: Authorizer,
    C: Clock,
    F: FnMut(Probe, &Deadline) -> Result<(), Error>,
{
    let started = Instant::now();
    let mut deadline =
        Deadline::new(request.limits.max_duration).with_cancellation(clock.cancellation());
    enforce_deadline(&Probes, &deadline)?;
    let (resolved_addresses, planned) = planned(request, authorizer, &deadline)?;
    let mut stats = Stats::default();
    let mut rtt = super::report::RttAccumulator::default();
    let mut active: Vec<Active<P::Stream>> = Vec::new();
    let mut next = 0usize;
    let mut next_start = clock.now();
    let mut evidence_bytes = 0usize;
    while next < planned.count || !active.is_empty() {
        enforce_deadline(&Probes, &deadline)?;
        let mut admission_held = false;
        while next < planned.count
            && active.len() < request.max_in_flight
            && clock.now() >= next_start
        {
            let Some(admitted) = admit_next(
                request, &planned, next, authorizer, &deadline, &provider, clock,
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
            enforce_deadline(&Probes, &deadline)?;
            let Some(probe) = settle_active(&mut active, index)? else {
                index += 1;
                continue;
            };
            evidence_bytes = evidence_bytes
                .checked_add(std::mem::size_of::<Probe>())
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
            emit(probe, &deadline)?;
        }
        if next < planned.count || !active.is_empty() {
            let mut wait = Duration::from_millis(1);
            if next < planned.count && active.len() < request.max_in_flight && !admission_held {
                wait = wait.min(next_start.saturating_duration_since(clock.now()));
            }
            if !wait.is_zero() {
                deadline
                    .start_accounting(Duration::ZERO)
                    .map_err(|source| Error::DurationLimit {
                        actual: source.actual,
                        limit: source.limit,
                    })?;
                clock.sleep(wait).map_err(|source| Error::Clock {
                    sequence: next as u64,
                    source: Box::new(source),
                })?;
            }
        }
    }
    enforce_deadline(&Probes, &deadline)?;
    stats.elapsed = started.elapsed();
    stats.rtt = rtt.finish();
    Ok(Summary {
        target: request.targets.to_string(),
        resolved_addresses,
        planned_duration: planned.planned_duration,
        stats,
    })
}

fn finish_probe<S: tcp::Stream>(
    entry: Active<S>,
    result: tcp::ConnectOutcome<S>,
) -> Result<Probe, Error> {
    let mut probe = Probe {
        sequence: entry.sequence,
        endpoint: entry.endpoint,
        attempt: entry.attempt,
        attempted: result.attempted,
        connect_succeeded: Some(result.result.is_ok()),
        outcome: Outcome::LocalError,
        scheduled_at: result.started_at,
        finished_at: Some(result.completed_at),
        elapsed: result.elapsed,
        local: None,
        error: None,
    };
    match result.result {
        Ok(stream) => {
            let peer = stream.peer_addr().map_err(|source| {
                execution(
                    entry.sequence,
                    tcp::Error::Evidence {
                        operation: "peer",
                        source,
                    },
                )
            })?;
            if peer != entry.endpoint {
                return Err(Error::InvalidEvidence {
                    sequence: entry.sequence,
                    message: "TCP provider returned a different peer endpoint".to_owned(),
                });
            }
            probe.local = Some(stream.local_addr().map_err(|source| {
                execution(
                    entry.sequence,
                    tcp::Error::Evidence {
                        operation: "local",
                        source,
                    },
                )
            })?);
            probe.outcome = if result.elapsed > entry.timeout {
                Outcome::DeadlineExpired
            } else {
                Outcome::Connected
            };
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
    if result.elapsed > entry.timeout {
        probe.outcome = Outcome::DeadlineExpired;
    }
    Ok(probe)
}

/// The socket evidence a failed connection publishes: the provider's own
/// socket error, or, for a connection that failed around it, an error of the
/// kind that failure means (a spent deadline timed out; cancellation
/// interrupted the attempt) that keeps it as its source.
fn socket_error(error: tcp::Error) -> io::Error {
    match error {
        tcp::Error::Socket(source) => source,
        error @ tcp::Error::DeadlineExceeded => io::Error::new(io::ErrorKind::TimedOut, error),
        error @ tcp::Error::Cancelled(_) => io::Error::new(io::ErrorKind::Interrupted, error),
        error => io::Error::other(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Socket {
        peer: SocketAddr,
        closed: Arc<AtomicUsize>,
    }
    impl Drop for Socket {
        fn drop(&mut self) {
            self.closed.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl Read for Socket {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("connect scan must not read application bytes")
        }
    }
    impl Write for Socket {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!("connect scan must not write application bytes")
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl tcp::Stream for Socket {
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.peer)
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:40000".parse().unwrap())
        }
        fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
        fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
    }
    struct Concurrent {
        active: AtomicUsize,
        peak: AtomicUsize,
        calls: AtomicUsize,
        closed: Arc<AtomicUsize>,
    }
    impl Provider for Concurrent {
        type Stream = Socket;
        fn connect(
            &self,
            endpoint: SocketAddr,
            _deadline: &Deadline,
        ) -> Result<Socket, tcp::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(20));
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(Socket {
                peer: endpoint,
                closed: Arc::clone(&self.closed),
            })
        }
    }
    #[test]
    fn connect_windows_overlap_with_stable_identity_and_closed_socket_evidence() {
        let request = Request {
            targets: crate::target::Target::Address("127.0.0.1".parse().unwrap()).into(),
            transport: Transport::Tcp,
            udp_payload: bytes::Bytes::new(),
            udp_profiles: Default::default(),
            address_family: crate::target::Family::Any,
            ports: vec![80, 81, 82, 83],
            attempts: 1,
            timeout: Duration::from_secs(1),
            probes_per_second: None,
            max_in_flight: 2,
            limits: super::super::Limits::default(),
        };
        let closed = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(Concurrent {
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
            closed: Arc::clone(&closed),
        });
        let policy = crate::policy::Policy::default();
        let mut authorizer = crate::policy::PolicyAuthorizer::for_packets(&policy);
        let report = run(
            &request,
            &mut authorizer,
            Arc::clone(&provider),
            &mut crate::clock::SystemClock,
        )
        .unwrap();
        assert_eq!(provider.peak.load(Ordering::SeqCst), 2);
        assert_eq!(closed.load(Ordering::SeqCst), 4);
        assert_eq!(report.summary.stats.connections_attempted, 4);
        assert_eq!(
            report
                .endpoints
                .iter()
                .flat_map(|endpoint| endpoint.probes.iter().map(|probe| probe.sequence))
                .collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
        let mut bounded = request;
        bounded.limits.max_probes = 1;
        assert!(
            run(
                &bounded,
                &mut authorizer,
                Arc::clone(&provider),
                &mut crate::clock::SystemClock
            )
            .is_err()
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 4);
    }

    /// Resolves each admitted connect by port: divisible by three connects,
    /// one more refuses, two more never answer, so one run exercises the
    /// sent/received/lost accounting and every RTT verdict class.
    struct Verdicts {
        closed: Arc<AtomicUsize>,
    }
    impl Provider for Verdicts {
        type Stream = Socket;
        fn connect(
            &self,
            endpoint: SocketAddr,
            _deadline: &Deadline,
        ) -> Result<Socket, tcp::Error> {
            match endpoint.port() % 3 {
                0 => Ok(Socket {
                    peer: endpoint,
                    closed: Arc::clone(&self.closed),
                }),
                1 => {
                    Err(io::Error::new(io::ErrorKind::ConnectionRefused, "scripted refusal").into())
                }
                _ => Err(io::Error::new(io::ErrorKind::TimedOut, "scripted silence").into()),
            }
        }
    }

    #[test]
    fn connect_scan_reports_rtt_statistics_across_verdicts() {
        let request = Request {
            targets: crate::target::Target::Address("127.0.0.1".parse().unwrap()).into(),
            transport: Transport::Tcp,
            udp_payload: bytes::Bytes::new(),
            udp_profiles: Default::default(),
            address_family: crate::target::Family::Any,
            ports: vec![90, 91, 92],
            attempts: 2,
            timeout: Duration::from_secs(5),
            probes_per_second: None,
            max_in_flight: 1,
            limits: super::super::Limits::default(),
        };
        let closed = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(Verdicts {
            closed: Arc::clone(&closed),
        });
        let policy = crate::policy::Policy::default();
        let mut authorizer = crate::policy::PolicyAuthorizer::for_packets(&policy);
        let report = run(
            &request,
            &mut authorizer,
            Arc::clone(&provider),
            &mut crate::clock::SystemClock,
        )
        .unwrap();

        let stats = &report.summary.stats;
        assert_eq!(stats.connections_scheduled, 6);
        assert_eq!(stats.connections_attempted, 6);
        assert_eq!(stats.connections_succeeded, 2);
        assert_eq!(stats.rtt.sent, 6);
        assert_eq!(stats.rtt.received, 4);
        assert_eq!(stats.rtt.lost, 2);
        let (Some(min), Some(avg), Some(max)) = (stats.rtt.min, stats.rtt.avg, stats.rtt.max)
        else {
            panic!("received probes must produce RTT samples");
        };
        assert!(
            min <= avg && avg <= max,
            "min {min:?} avg {avg:?} max {max:?}"
        );
        let endpoint_verdicts: Vec<_> = report
            .endpoints
            .iter()
            .map(|endpoint| (endpoint.port, endpoint.classification))
            .collect();
        assert_eq!(
            endpoint_verdicts,
            [
                (90, Classification::Open),
                (91, Classification::Closed),
                (92, Classification::Timeout),
            ]
        );
        assert_eq!(closed.load(Ordering::SeqCst), 2);
    }
}
