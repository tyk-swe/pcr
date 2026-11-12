// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::borrow::Borrow;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::registry::Registry;

use crate::client::admission::approve_operation;
use crate::clock::Clock;
use crate::engine::execution::{Context, Executor, Shared};
use crate::policy::{Authorizer, DnsOperation, LimitOverflow, Operation, WireLimits};
use crate::target::ResolveTarget;
use crate::{Sink, Stats};
use packetcraftr_core::error::BoundaryError;

use super::engine::PreparedOperation;
use super::executor::{Exchange, TcpQuerier};
use super::plan::batch_limits;
use super::report::Observed;
use super::{Error, QueryType};

pub const MAX_QUESTIONS: usize = 256;

/// Every question shares the first one's server, port, route, and collection bounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub questions: Vec<super::Request>,
}

impl Request {
    pub fn validate(&self) -> Result<(), Error> {
        let questions = &self.questions;
        if questions.is_empty() || questions.len() > MAX_QUESTIONS {
            return Err(Error::InvalidLimit {
                field: "questions",
                value: questions.len() as u64,
                reason: format!("must be within 1..={MAX_QUESTIONS}"),
            });
        }
        let first = &questions[0];
        if let Some(index) = questions.iter().position(|question| {
            question.server != first.server || question.server_port != first.server_port
        }) {
            return Err(Error::InvalidLimit {
                field: "questions",
                value: index as u64,
                reason: "all questions must share the same server and server port".to_owned(),
            });
        }
        if let Some(index) = questions.iter().position(|question| {
            question.route != first.route || question.collection != first.collection
        }) {
            return Err(Error::InvalidLimit {
                field: "questions",
                value: index as u64,
                reason: "all questions must share the same route and collection bounds".to_owned(),
            });
        }
        Ok(())
    }
}

/// The traffic limits `questions` need together, including the
/// `neighbor_attempts` requests a link-layer route may send before each UDP
/// packet.
pub(crate) fn limits<Q>(
    questions: impl IntoIterator<Item = Q>,
    neighbor_attempts: u64,
) -> Result<DnsOperation, Error>
where
    Q: Borrow<super::Request>,
{
    let mut failure = None;
    let operations = questions.into_iter().map_while(|question| {
        let question = question.borrow();
        question_limits(question, neighbor_attempts)
            .map_err(|error| failure = Some(error))
            .ok()
    });
    let limits = batch_limits(operations)?;
    failure.map_or(Ok(limits), Err)
}

fn question_limits(
    question: &super::Request,
    neighbor_attempts: u64,
) -> Result<DnsOperation, Error> {
    let prepared = PreparedOperation::new(question)?;
    with_neighbor_requests(question, prepared.limits, neighbor_attempts)
}

/// One validated batch with its per-question operations and combined limits.
/// Building it validates the batch once, so callers never index raw questions
/// or rebuild the prepared set before execution.
pub(crate) struct Prepared<'a> {
    questions: &'a [super::Request],
    operations: Vec<PreparedOperation<'a>>,
    limits: DnsOperation,
    max_duration: Duration,
}

impl<'a> Prepared<'a> {
    pub(crate) fn new(request: &'a Request, neighbor_attempts: u64) -> Result<Self, Error> {
        request.validate()?;
        let questions = request.questions.as_slice();
        let mut operations = Vec::with_capacity(questions.len());
        let mut limits = Vec::with_capacity(questions.len());
        for question in questions {
            let prepared = PreparedOperation::new(question)?;
            limits.push(with_neighbor_requests(
                question,
                prepared.limits,
                neighbor_attempts,
            )?);
            operations.push(prepared);
        }
        let limits = batch_limits(limits.into_iter())?;
        let max_duration = questions
            .iter()
            .map(|question| question.limits.max_duration)
            .min()
            .expect("a validated batch is non-empty");
        Ok(Self {
            questions,
            operations,
            limits,
            max_duration,
        })
    }

    pub(crate) const fn max_duration(&self) -> Duration {
        self.max_duration
    }

    pub(crate) fn first(&self) -> &'a super::Request {
        &self.questions[0]
    }
}

/// Charges `attempts` neighbor requests before each of a question's UDP
/// packets whose route may resolve a link-layer neighbor: an unanswered
/// resolution is not remembered, so every packet may ask again.
fn with_neighbor_requests(
    question: &super::Request,
    limits: DnsOperation,
    attempts: u64,
) -> Result<DnsOperation, Error> {
    if question.route.link_mode == packetcraftr_netio::link::Mode::Layer3 {
        return Ok(limits);
    }
    // A multicast or limited-broadcast server's link address follows from its
    // own, so no request precedes a query to it.
    if let crate::target::Target::Address(address) = &question.server
        && !crate::neighbor::needs_resolution(*address)
    {
        return Ok(limits);
    }
    // A server of unknown family is charged the larger solicitation.
    let request_bytes = match &question.server {
        crate::target::Target::Address(address) => crate::neighbor::request_wire_bytes(*address),
        _ => crate::neighbor::IPV6_REQUEST_BYTES,
    };
    let udp = limits.udp();
    let requests = udp.packets().checked_mul(attempts).ok_or(LimitOverflow)?;
    let packets = udp.packets().checked_add(requests).ok_or(LimitOverflow)?;
    let bytes = requests
        .checked_mul(request_bytes)
        .and_then(|requests| requests.checked_add(udp.wire_bytes()))
        .ok_or(LimitOverflow)?;
    Ok(DnsOperation::new(
        WireLimits::new(packets, bytes),
        limits.tcp(),
    )?)
}

#[derive(Clone, Debug)]
pub struct Event {
    pub question: usize,
    pub event: super::Event,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionStatus {
    Completed,
    Failed,
    Unattempted,
}

impl QuestionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Unattempted => "unattempted",
        }
    }
}

impl std::fmt::Display for QuestionStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct Question<R = super::Report> {
    pub query_name: String,
    pub query_type: QueryType,
    pub transaction_id: u16,
    pub outcome: Outcome<R>,
}

#[derive(Debug)]
pub enum Outcome<R> {
    Completed(R),
    Failed(Error),
    Unattempted,
}

impl<R> Outcome<R> {
    pub const fn status(&self) -> QuestionStatus {
        match self {
            Self::Completed(_) => QuestionStatus::Completed,
            Self::Failed(_) => QuestionStatus::Failed,
            Self::Unattempted => QuestionStatus::Unattempted,
        }
    }

    pub const fn result(&self) -> Option<&R> {
        match self {
            Self::Completed(result) => Some(result),
            Self::Failed(_) | Self::Unattempted => None,
        }
    }

    pub const fn error(&self) -> Option<&Error> {
        match self {
            Self::Failed(error) => Some(error),
            Self::Completed(_) | Self::Unattempted => None,
        }
    }
}

impl<R> Question<R> {
    fn new(request: &super::Request, outcome: Outcome<R>) -> Self {
        Self {
            query_name: request.query_name.clone(),
            query_type: request.query_type,
            transaction_id: request.transaction_id,
            outcome,
        }
    }

    fn unattempted(request: &super::Request) -> Self {
        Self::new(request, Outcome::Unattempted)
    }

    fn failed(request: &super::Request, error: Error) -> Self {
        Self::new(request, Outcome::Failed(error))
    }

    fn completed(request: &super::Request, result: R) -> Self {
        Self::new(request, Outcome::Completed(result))
    }
}

#[derive(Debug)]
pub struct Report {
    pub server: String,
    pub server_port: u16,
    pub questions: Vec<Question>,
    pub stats: Stats,
}

#[derive(Debug)]
pub struct Aggregate {
    pub server: String,
    pub server_port: u16,
    pub questions: Vec<Question<super::Aggregate>>,
    pub stats: Stats,
}

#[derive(Clone, Default)]
pub struct Collector(Shared<Vec<(usize, Observed)>>);

impl Sink<Event> for Collector {
    fn delivery(&self) -> crate::Delivery {
        crate::Delivery::Cooperative
    }

    type Ack = ();

    fn publish(&mut self, event: Event) -> Result<(), BoundaryError> {
        self.0.update(|questions| match questions.last_mut() {
            Some((question, observed)) if *question == event.question => {
                observed.observe(event.event);
            }
            _ => {
                let mut observed = Observed::default();
                observed.observe(event.event);
                questions.push((event.question, observed));
            }
        });
        Ok(())
    }
}

impl Collector {
    pub fn finish(self, report: Report) -> Result<Aggregate, Error> {
        let mut observed = self.0.take().into_iter().peekable();
        let Report {
            server,
            server_port,
            questions,
            stats,
        } = report;
        let questions = questions
            .into_iter()
            .enumerate()
            .map(|(index, question)| {
                while observed.next_if(|(seen, _)| *seen < index).is_some() {}
                let events = observed
                    .next_if(|(seen, _)| *seen == index)
                    .map(|(_, events)| events)
                    .unwrap_or_default();
                Ok(Question {
                    query_name: question.query_name,
                    query_type: question.query_type,
                    transaction_id: question.transaction_id,
                    outcome: match question.outcome {
                        Outcome::Completed(report) => Outcome::Completed(events.finish(report)?),
                        Outcome::Failed(error) => Outcome::Failed(error),
                        Outcome::Unattempted => Outcome::Unattempted,
                    },
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(Aggregate {
            server,
            server_port,
            questions,
            stats,
        })
    }
}

/// The inter-question wait precedes the next question's first attempt, so its failures name it.
const FIRST_ATTEMPT: u32 = 1;

/// Authorizes the combined worst-case traffic limits before discovery.
pub(super) fn run<A, E, C, F>(
    prepared: Prepared<'_>,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    deadline: &mut Deadline,
    mut observe: F,
) -> Result<Report, Error>
where
    A: Authorizer + ResolveTarget,
    E: Executor<Exchange> + TcpQuerier,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    let Prepared {
        questions: requests,
        operations: prepared,
        limits,
        ..
    } = prepared;
    let mut stop = deadline.enforce().is_err();
    if !stop {
        approve_operation::<_, Error>(authorizer, Operation::Dns(limits), deadline)?;
    }
    let mut questions = Vec::with_capacity(requests.len());
    let mut stats = Stats::default();
    let mut previous_delay: Option<Duration> = None;
    for (index, (request, mut prepared)) in requests.iter().zip(prepared).enumerate() {
        // Cancellation wins over elapsed-time reporting, matching every other deadline gate.
        if stop || deadline.enforce().is_err() {
            questions.push(Question::unattempted(request));
            continue;
        }
        // Pace across question boundaries too; a batch must not become an unpaced burst.
        if let Some(previous) = previous_delay {
            let delay = previous.max(prepared.delay);
            if !delay.is_zero() {
                let mut pause = Context::new(&mut *deadline, &mut *clock);
                let waited = pause.pace(u64::from(FIRST_ATTEMPT), delay).and_then(|()| {
                    stats.checked_add_assign(&pause.into_stats()).map_err(|_| {
                        Error::StatisticsOverflow {
                            attempt: FIRST_ATTEMPT,
                        }
                    })
                });
                if let Err(error) = waited {
                    stop = true;
                    questions.push(match error {
                        Error::Cancelled(_) | Error::DurationLimit { .. } => {
                            Question::unattempted(request)
                        }
                        error => Question::failed(request, error),
                    });
                    continue;
                }
            }
        }
        previous_delay = Some(prepared.delay);
        let result = prepared.execute(
            authorizer,
            registry,
            executor,
            clock,
            &mut *deadline,
            |event, deadline| {
                observe(
                    Event {
                        question: index,
                        event,
                    },
                    deadline,
                )
            },
        );
        stats
            .checked_add_assign(&prepared.report.stats)
            .map_err(|_| Error::StatisticsOverflow {
                attempt: request.attempts,
            })?;
        match result {
            Ok(()) => questions.push(Question::completed(request, prepared.report)),
            Err(error @ Error::Output { .. }) => return Err(error),
            Err(error) => {
                stop = matches!(error, Error::Cancelled(_) | Error::DurationLimit { .. });
                questions.push(Question::failed(request, error));
            }
        }
    }
    Ok(Report {
        server: requests[0].server.to_string(),
        server_port: requests[0].server_port,
        questions,
        stats,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use super::{Prepared, Request};
    use crate::dns::{Limits, QueryType, TransportMode};
    use crate::target::{Family, Target};

    fn question(name: &str) -> crate::dns::Request {
        crate::dns::Request {
            server: Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            address_family: Family::Any,
            server_port: 53,
            source_port: 12_345,
            query_name: name.to_owned(),
            query_type: QueryType::A,
            transaction_id: 7,
            recursion_desired: true,
            edns: None,
            transport: TransportMode::Udp,
            attempts: 2,
            timeout: Duration::from_millis(250),
            queries_per_second: None,
            limits: Limits {
                max_duration: Duration::from_secs(30),
                ..Limits::default()
            },
            route: crate::route::Options::default(),
            collection: crate::exchange::Collection::default(),
        }
    }

    #[test]
    fn empty_batch_is_rejected_before_indexing() {
        let error = match Prepared::new(&Request { questions: Vec::new() }, 1) {
            Ok(_) => panic!("an empty batch must be rejected"),
            Err(error) => error,
        };
        assert!(
            matches!(error, super::Error::InvalidLimit { field: "questions", .. }),
            "expected a questions limit error, got {error:?}"
        );
    }

    #[test]
    fn prepared_limits_match_the_authorization_entry_point() {
        let questions = vec![question("a.test"), question("b.test")];
        let request = Request {
            questions: questions.clone(),
        };
        let expected = super::limits(questions.iter(), 3).unwrap();
        let prepared = Prepared::new(&request, 3).unwrap();
        assert_eq!(prepared.limits, expected);
    }
}
