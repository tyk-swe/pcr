// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Optional PTR lookups for scanned hosts. They run through the DNS workflow,
//! so the policy authorizes the server and every query is bounded like any
//! other.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;

use crate::clock::Clock;
use crate::dns::{self, batch};
use crate::providers::{PacketProviders, TargetProviders, TcpProviders};
use crate::scan;
use crate::scan::discovery::{Host, State};
use crate::target::Target;
use crate::{Client, Stats};

use super::Error;
use super::request::ReverseDns;

/// A PTR lookup's result: what the server answered, never authenticated
/// identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReverseLookup {
    pub query_name: String,
    pub status: batch::QuestionStatus,
    pub outcome: Option<dns::Outcome>,
    pub response_code: Option<u16>,
    /// Distinct PTR names in answer order, each with its trailing dot.
    pub names: Vec<String>,
    /// Whether the scan's evidence byte limit, which bounds the names kept
    /// across every lookup, dropped later names of this answer.
    pub names_truncated: bool,
    pub error: Option<String>,
}

impl ReverseLookup {
    /// A lookup that ended without a DNS workflow result.
    pub(super) fn ended(
        query_name: String,
        status: batch::QuestionStatus,
        error: Option<String>,
    ) -> Self {
        Self {
            query_name,
            status,
            outcome: None,
            response_code: None,
            names: Vec::new(),
            names_truncated: false,
            error,
        }
    }
}

impl From<batch::Question<dns::Aggregate>> for ReverseLookup {
    fn from(question: batch::Question<dns::Aggregate>) -> Self {
        let result = question.result.as_ref();
        Self {
            query_name: question.query_name,
            status: question.status,
            outcome: result.map(|result| result.report().completion.outcome()),
            response_code: result
                .and_then(|result| result.report().completion.response())
                .map(|metadata| metadata.response_code),
            names: result
                .and_then(dns::Aggregate::response)
                .map(|response| {
                    dns::ptr_names(&response.answers)
                        .iter()
                        .map(ToString::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            names_truncated: false,
            error: question.error.as_ref().map(ToString::to_string),
        }
    }
}

/// Each host's lookup by position, plus the lookups' exchange statistics,
/// absent when no host was looked up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReverseLookups {
    pub lookups: Vec<Option<ReverseLookup>>,
    pub stats: Option<Stats>,
}

/// One server for every question. The scan's attempts, timeout, rate, and
/// evidence limits bound each question, and its `--max-duration` bounds the
/// lookups together with the scan.
#[derive(Clone, Debug)]
pub(super) struct Lookup {
    pub(super) template: dns::Request,
}

impl Lookup {
    pub(super) fn new(reverse: &ReverseDns, scan: &scan::Request) -> Result<Self, Error> {
        if let Target::ScopedAddress(scoped) = &reverse.server {
            return Err(dns::Error::ScopedServer {
                server: scoped.to_string(),
            }
            .into());
        }
        let lookup = Self {
            template: dns::Request {
                server: reverse.server.clone(),
                address_family: crate::target::Family::Any,
                server_port: reverse.server_port,
                source_port: 0,
                query_name: String::new(),
                query_type: dns::QueryType::PTR,
                transaction_id: 0,
                recursion_desired: true,
                edns: None,
                transport: reverse.transport,
                attempts: scan.attempts,
                timeout: scan.timeout,
                queries_per_second: scan.probes_per_second,
                limits: dns::Limits {
                    message: dns::MessageLimits::default(),
                    max_evidence_frames: scan.limits.max_evidence_frames,
                    max_evidence_bytes: scan.limits.max_evidence_bytes,
                    max_undecoded: scan.limits.max_undecoded,
                    max_duration: scan.limits.max_duration,
                },
                route: scan.route.clone(),
                collection: scan.collection.clone(),
            },
        };
        if lookup.template.transport != dns::TransportMode::Tcp {
            // Reject invalid caller settings before narrowing them for a
            // batch, so synthesis cannot hide an unusable collection.
            lookup
                .template
                .collection
                .validate()
                .map_err(|source| dns::Error::Execution {
                    attempt: 1,
                    source: BoundaryError::from_error(source),
                })?;
        }
        // Check the smallest share that any batch may assign. This uses
        // the same synthesis and admission checks as the eventual query.
        let question = lookup.question(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            lookup.template.limits.max_duration,
            lookup.batch_size(),
        )?;
        question.validate()?;
        question.validate_capture()?;
        Ok(lookup)
    }

    /// Looks up hosts that responded to discovery, or every host when
    /// discovery did not run; a host discovery found silent is not looked
    /// up. Returns one entry per host plus the exchanges' statistics for
    /// the command's own accounting. A failed batch fails its questions
    /// rather than the scan, whose evidence is already measured. Cancellation
    /// and pacing failures stop the operation with their typed errors. The
    /// scan's evidence byte limit bounds the names kept across every lookup.
    pub(super) fn run<P, K>(
        &self,
        client: &Client<P, K>,
        hosts: &[Host],
        started: Instant,
        last_sent: Option<Instant>,
    ) -> Result<(Vec<Option<ReverseLookup>>, Stats), dns::Error>
    where
        P: PacketProviders + TargetProviders + TcpProviders,
        K: Clock,
    {
        let deadline = client.deadline(
            self.template
                .limits
                .max_duration
                .saturating_sub(client.now().saturating_duration_since(started)),
        );
        deadline.check_cancelled()?;
        // A batch paces its own questions; this pause keeps the scan's rate
        // between the last transmission before a batch, `last_sent` by the scan
        // or sent by an earlier batch, and the batch's first question.
        let pause = self
            .template
            .queries_per_second
            .and_then(|rate| Duration::from_secs(1).checked_div(rate))
            .unwrap_or_default();
        let authorized = self.authorize(client, hosts);
        // Questions the policy refused are never sent, so no batch waits for
        // them.
        let pause = if authorized.is_ok() {
            pause
        } else {
            Duration::ZERO
        };
        batched(
            hosts,
            pause,
            self.batch_size(),
            last_sent,
            &deadline,
            self.template.limits.max_evidence_bytes,
            || client.now(),
            |waited| {
                client
                    .clock
                    .sleep(waited, &deadline)
                    .map_err(|source| dns::Error::Clock {
                        attempt: 1,
                        source: Box::new(source),
                    })
            },
            |addresses, remaining| match &authorized {
                Ok(()) => self.lookup(client, addresses, remaining),
                Err(error) => Ok((
                    addresses
                        .iter()
                        .map(|address| {
                            ReverseLookup::ended(
                                dns::reverse_name(*address),
                                batch::QuestionStatus::Failed,
                                Some(error.clone()),
                            )
                        })
                        .collect(),
                    Stats::default(),
                    None,
                )),
            },
        )
    }

    /// Authorizes every lookup `hosts` may need as one operation, so that
    /// splitting them into batches never restarts the policy's packet and
    /// byte budgets.
    pub(super) fn authorize<P, K>(
        &self,
        client: &Client<P, K>,
        hosts: &[Host],
    ) -> Result<(), String>
    where
        P: PacketProviders + TargetProviders + TcpProviders,
        K: Clock,
    {
        let mut failure = None;
        let questions = hosts
            .iter()
            .filter(|host| host.state != State::NoResponse)
            .map_while(|host| {
                self.question(host.address, self.template.limits.max_duration, 1)
                    .map_err(|error| failure = Some(error.to_string()))
                    .ok()
            });
        let limits = client
            .dns_limits(questions)
            .map_err(|error| error.to_string());
        if let Some(error) = failure {
            return Err(error);
        }
        client
            .policy()
            .authorize(crate::policy::Operation::Dns(limits?))
            .map_err(|error| error.to_string())
    }

    pub(super) fn lookup<P, K>(
        &self,
        client: &Client<P, K>,
        addresses: &[IpAddr],
        remaining: Duration,
    ) -> Result<(Vec<ReverseLookup>, Stats, Option<Instant>), dns::Error>
    where
        P: PacketProviders + TargetProviders + TcpProviders,
        K: Clock,
    {
        let ended = |status, error: Option<String>| {
            Ok((
                addresses
                    .iter()
                    .map(|address| {
                        ReverseLookup::ended(dns::reverse_name(*address), status, error.clone())
                    })
                    .collect(),
                Stats::default(),
                None,
            ))
        };
        if remaining.is_zero() {
            return ended(batch::QuestionStatus::Unattempted, None);
        }
        let questions = match self.questions(addresses, remaining) {
            Ok(questions) => questions,
            Err(error) => {
                return ended(batch::QuestionStatus::Failed, Some(error.to_string()));
            }
        };
        let collector = batch::Collector::default();
        match client
            .dns_batch(batch::Request { questions }, collector.clone())
            .and_then(|report| collector.finish(report))
        {
            Ok(aggregate) => {
                let sent = last_batch_send(&aggregate.questions, &aggregate.stats, client.now());
                Ok((
                    aggregate
                        .questions
                        .into_iter()
                        // DNS batches retain failures as question data. These
                        // interruptions instead stop the follow-up operation,
                        // preserving the clock's original error source.
                        .map(|question| match question {
                            batch::Question {
                                error:
                                    Some(
                                        error @ (dns::Error::Cancelled(_)
                                        | dns::Error::Clock { .. }),
                                    ),
                                ..
                            } => Err(error),
                            question => Ok(ReverseLookup::from(question)),
                        })
                        .collect::<Result<_, _>>()?,
                    aggregate.stats,
                    sent,
                ))
            }
            // A window too short for one question's planned attempts sends
            // none of them.
            Err(dns::Error::DurationLimit { .. }) => {
                ended(batch::QuestionStatus::Unattempted, None)
            }
            Err(error @ (dns::Error::Cancelled(_) | dns::Error::Clock { .. })) => Err(error),
            Err(error) => ended(batch::QuestionStatus::Failed, Some(error.to_string())),
        }
    }

    /// One batch's questions. A batch retains every question's evidence
    /// until it ends, so they share the scan's evidence limits rather than
    /// each taking them whole.
    pub(super) fn questions(
        &self,
        addresses: &[IpAddr],
        remaining: Duration,
    ) -> Result<Vec<dns::Request>, BoundaryError> {
        let share = addresses.len().max(1);
        addresses
            .iter()
            .map(|address| self.question(*address, remaining, share))
            .collect()
    }

    /// The most lookups one batch holds, so that each question's share of
    /// the scan's evidence limits still holds a frame.
    pub(super) fn batch_size(&self) -> usize {
        let limits = &self.template.limits;
        let snap_length = self.template.collection.capture.snap_length.max(1);
        batch::MAX_QUESTIONS
            .min(limits.max_evidence_frames)
            .min(limits.max_evidence_bytes / snap_length)
            .max(1)
    }

    fn question(
        &self,
        address: IpAddr,
        max_duration: Duration,
        share: usize,
    ) -> Result<dns::Request, BoundaryError> {
        let source_port = if self.template.transport == dns::TransportMode::Tcp {
            0
        } else {
            dns::unpredictable_source_port()?
        };
        let mut question = dns::Request {
            query_name: dns::reverse_name(address),
            transaction_id: dns::unpredictable_transaction_id()?,
            source_port,
            limits: dns::Limits {
                max_duration,
                ..self.template.limits
            },
            ..self.template.clone()
        };
        question.limits.max_evidence_frames /= share;
        question.limits.max_evidence_bytes /= share;
        question.limits.max_undecoded /= share;
        if question.transport != dns::TransportMode::Tcp {
            let frames = question
                .limits
                .max_evidence_frames
                .min(question.collection.max_responses);
            question.limits.max_evidence_frames = frames;
            question.limits.max_undecoded = question.limits.max_undecoded.min(frames);
            // The synthesized question's capture configuration must fit
            // its evidence share before the DNS executor admits any I/O.
            question.collection.capture.max_frames = frames;
            question.collection.capture.max_bytes = question
                .collection
                .capture
                .max_bytes
                .min(question.limits.max_evidence_bytes);
            question.collection.max_responses = frames;
            question.collection.max_unmatched_frames =
                question.collection.max_unmatched_frames.min(frames);
        }
        Ok(question)
    }
}

/// Looks `hosts` up in batches spaced by `pause` until `deadline`, keeping
/// their names within `name_budget` bytes. Cancellation and pacing failures
/// stop the operation before any further question waits or sends.
#[allow(clippy::too_many_arguments)]
pub(super) fn batched(
    hosts: &[Host],
    pause: Duration,
    batch_size: usize,
    last_sent: Option<Instant>,
    deadline: &Deadline,
    mut name_budget: usize,
    now: impl Fn() -> Instant,
    mut sleep: impl FnMut(Duration) -> Result<(), dns::Error>,
    mut lookup: impl FnMut(
        &[IpAddr],
        Duration,
    ) -> Result<(Vec<ReverseLookup>, Stats, Option<Instant>), dns::Error>,
) -> Result<(Vec<Option<ReverseLookup>>, Stats), dns::Error> {
    deadline.check_cancelled()?;
    let mut names: Vec<Option<ReverseLookup>> = hosts.iter().map(|_| None).collect();
    let mut statistics = Stats::default();
    let selected: Vec<usize> = hosts
        .iter()
        .enumerate()
        .filter(|(_, host)| host.state != State::NoResponse)
        .map(|(index, _)| index)
        .collect();
    let mut last_sent = last_sent;
    for chunk in selected.chunks(batch_size) {
        deadline.check_cancelled()?;
        // Only what remains of the pause since the last transmission is owed;
        // its replies' wait already spaced it from this batch.
        let owed = last_sent.map_or(Duration::ZERO, |sent| {
            pause.saturating_sub(now().saturating_duration_since(sent))
        });
        let waited = owed.min(deadline.remaining().unwrap_or_default());
        if !waited.is_zero() {
            let slept = sleep(waited);
            // As at other pacing boundaries, cancellation wins even if a
            // fallible clock also reports a failure while being interrupted.
            deadline.check_cancelled()?;
            slept?;
            statistics.elapsed = statistics.elapsed.saturating_add(waited);
        }
        deadline.check_cancelled()?;
        let addresses: Vec<IpAddr> = chunk.iter().map(|&index| hosts[index].address).collect();
        let looked_up = lookup(&addresses, deadline.remaining().unwrap_or_default());
        deadline.check_cancelled()?;
        let (lookups, stats, sent) = looked_up?;
        // A TCP lookup counts no packets but still reports that it sent.
        if sent.is_some() || stats.packets_attempted > 0 {
            last_sent = Some(sent.unwrap_or_else(&now));
        }
        for (&index, mut lookup) in chunk.iter().zip(lookups) {
            retain_names(&mut lookup, &mut name_budget);
            names[index] = Some(lookup);
        }
        // A failed batch reports no statistics; the bounded questions
        // cannot overflow these counters.
        let _ = statistics.checked_add_assign(&stats);
    }
    Ok((names, statistics))
}

/// Keeps `lookup`'s names while what they occupy fits `budget`, marking the
/// lookup when later names were dropped.
pub(super) fn retain_names(lookup: &mut ReverseLookup, budget: &mut usize) {
    let kept = lookup
        .names
        .iter()
        .take_while(|name| {
            let held = size_of::<String>().saturating_add(name.len());
            budget
                .checked_sub(held)
                .map(|left| *budget = left)
                .is_some()
        })
        .count();
    if kept < lookup.names.len() {
        lookup.names.truncate(kept);
        lookup.names_truncated = true;
    }
}

/// Each host's lookup by position, or nothing when no server was requested,
/// plus the lookups' exchange statistics, absent when no host was looked up.
pub(super) fn names<P, K>(
    lookup: Option<&Lookup>,
    client: &Client<P, K>,
    hosts: &[Host],
    started: Instant,
    last_sent: Option<Instant>,
) -> Result<Option<ReverseLookups>, dns::Error>
where
    P: PacketProviders + TargetProviders + TcpProviders,
    K: Clock,
{
    let Some(lookup) = lookup else {
        return Ok(None);
    };
    let (lookups, stats) = lookup.run(client, hosts, started, last_sent)?;
    let looked_up = lookups.iter().any(Option::is_some);
    Ok(Some(ReverseLookups {
        lookups,
        stats: looked_up.then_some(stats),
    }))
}

/// When a batch last sent, observed at `now`. A failed question keeps no
/// attempt evidence, so a batch that failed one after sending anything is
/// taken to have sent last as it ended, which spaces the next batch at least
/// as far as its rate needs.
pub(super) fn last_batch_send(
    questions: &[batch::Question<dns::Aggregate>],
    stats: &Stats,
    now: Instant,
) -> Option<Instant> {
    let failed = questions
        .iter()
        .any(|question| question.status == batch::QuestionStatus::Failed);
    if failed && (stats.bytes > 0 || stats.packets_attempted > 0) {
        return Some(now);
    }
    // An attempt's wall-clock `sent_at` is wire evidence, not a pacing marker:
    // any sent attempt marks the batch's end conservatively.
    questions
        .iter()
        .filter_map(|question| question.result.as_ref())
        .flat_map(dns::Aggregate::attempts)
        .any(|attempt| attempt.sent_at().is_some())
        .then_some(now)
}

/// A conservative monotonic marker for a stage that sent: the latest of
/// `sent`'s markers, or `now` when packets were `attempted` with no marker.
/// Wire `sent_at` fields stay wall-clock evidence and never reach pacing.
pub(super) fn last_transmission(
    attempted: bool,
    sent: impl IntoIterator<Item = Instant>,
    now: Instant,
) -> Option<Instant> {
    attempted.then(|| sent.into_iter().max().unwrap_or(now))
}
