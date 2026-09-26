// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded multi-question DNS batches under one operation deadline, run by
//! [`Client::dns_batch`](crate::Client::dns_batch).

use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::registry::Registry;

use crate::clock::Clock;
use crate::execution::{Context, Executor, Shared};
use crate::policy::{Authorizer, Operation};
use crate::target::{ResolveTarget, approve_operation};
use crate::{Sink, Stats};
use packetcraftr_core::error::BoundaryError;

use super::engine::{Attempts, PreparedOperation};
use super::executor::{Exchange, TcpQuerier};
use super::plan::batch_limits;
use super::report::Observed;
use super::{Error, QueryType};

pub const MAX_QUESTIONS: usize = 256;

/// The questions of one batch, in the order they run. Every question shares
/// the first one's server, server port, route, and collection bounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub questions: Vec<super::Request>,
}

impl Request {
    /// Rejects an empty or oversized batch and questions that disagree on
    /// the server or on the route and collection their exchanges share.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLimit`] for the `questions` field.
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

    /// The one deadline every question shares: the shortest
    /// `limits.max_duration` in the batch.
    pub(super) fn max_duration(&self) -> Result<Duration, Error> {
        self.validate()?;
        Ok(self
            .questions
            .iter()
            .map(|question| question.limits.max_duration)
            .min()
            .expect("a validated batch is non-empty"))
    }
}

/// One event of the question at index `question` in the batch.
#[derive(Clone, Debug)]
pub struct Event {
    pub question: usize,
    pub event: super::Event,
}

/// How one batch question ended, in the request's declared order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionStatus {
    /// The question ran to completion; `result` carries it, with the
    /// completed [`Outcome`](super::Outcome) (which may itself be a timeout or
    /// failure classification).
    Completed,
    /// The question started — or reached its pre-execution gates — and
    /// returned an error; `error` carries the classified failure.
    Failed,
    /// The shared deadline or a cancellation stopped the batch before this
    /// question began; no request traffic was generated for it.
    Unattempted,
}

impl QuestionStatus {
    /// The stable text and structured-output name.
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

/// How one batch question ended, in input order. `R` is the question's
/// terminal [`Report`](super::Report) in a batch [`Report`], and its
/// [`Aggregate`](super::Aggregate) in a batch [`Aggregate`].
#[derive(Debug)]
pub struct Question<R = super::Report> {
    pub query_name: String,
    pub query_type: QueryType,
    pub transaction_id: u16,
    pub status: QuestionStatus,
    /// Present exactly when `status` is [`QuestionStatus::Completed`].
    pub result: Option<R>,
    /// The classified failure; present exactly when `status` is
    /// [`QuestionStatus::Failed`].
    pub error: Option<Error>,
}

impl<R> Question<R> {
    fn ended(request: &super::Request, status: QuestionStatus) -> Self {
        Self {
            query_name: request.query_name.clone(),
            query_type: request.query_type,
            transaction_id: request.transaction_id,
            status,
            result: None,
            error: None,
        }
    }

    fn failed(request: &super::Request, error: Error) -> Self {
        Self {
            error: Some(error),
            ..Self::ended(request, QuestionStatus::Failed)
        }
    }
}

/// The terminal result of one batch: one entry per declared question, in
/// input order, plus the exact totals confirmed across all questions.
#[derive(Debug)]
pub struct Report {
    /// The server target every question shared, exactly as declared.
    pub server: String,
    pub server_port: u16,
    pub questions: Vec<Question>,
    pub stats: Stats,
}

impl Report {
    /// Counts questions by status as `(completed, failed, unattempted)`.
    pub fn status_counts(&self) -> (usize, usize, usize) {
        let mut counts = (0, 0, 0);
        for question in &self.questions {
            match question.status {
                QuestionStatus::Completed => counts.0 += 1,
                QuestionStatus::Failed => counts.1 += 1,
                QuestionStatus::Unattempted => counts.2 += 1,
            }
        }
        counts
    }
}

/// Every event of one batch joined with its [`Report`]: each completed
/// question carries its full [`Aggregate`](super::Aggregate).
#[derive(Debug)]
pub struct Aggregate {
    pub server: String,
    pub server_port: u16,
    pub questions: Vec<Question<super::Aggregate>>,
    pub stats: Stats,
}

/// A sink that rebuilds the batch [`Aggregate`] from published events. Pass
/// a clone to [`Client::dns_batch`](crate::Client::dns_batch) and
/// [`finish`](Self::finish) the one kept with the report it returns.
#[derive(Clone, Default)]
pub struct Collector(Shared<Vec<(usize, Observed)>>);

impl Sink<Event> for Collector {
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
    /// Joins each completed question's events with its terminal report.
    /// Events of a question that failed are not retained.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IncoherentReport`] when a question's events disagree
    /// with its report.
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
                    status: question.status,
                    result: question
                        .result
                        .map(|report| events.finish(report))
                        .transpose()?,
                    error: question.error,
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

/// The wait between questions precedes the next question's first attempt,
/// so its failures name that attempt.
const FIRST_ATTEMPT: u32 = 1;

/// Runs the batch's questions in input order under `deadline`.
///
/// Prepares and authorizes the combined worst-case traffic limits before
/// discovery. Cancellation or deadline exhaustion leaves remaining questions
/// [`QuestionStatus::Unattempted`]; other question failures are
/// [`QuestionStatus::Failed`] and allow the batch to continue. Output failures
/// stop execution immediately.
pub(super) fn run<A, E, C, F>(
    request: &Request,
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
    request.validate()?;
    let requests = &request.questions;
    let prepared = requests
        .iter()
        .map(PreparedOperation::new)
        .collect::<Result<Vec<_>, _>>()?;
    let limits = batch_limits(prepared.iter().map(|prepared| prepared.limits))?;
    let mut stop = deadline.enforce().is_err();
    if !stop {
        approve_operation(authorizer, Operation::Dns(limits), deadline, &Attempts)?;
    }
    let mut questions = Vec::with_capacity(requests.len());
    let mut stats = Stats::default();
    let mut previous_delay: Option<Duration> = None;
    for (index, (request, mut prepared)) in requests.iter().zip(prepared).enumerate() {
        // Cancellation wins over elapsed-time reporting, matching every other
        // deadline gate.
        if stop || deadline.enforce().is_err() {
            questions.push(Question::ended(request, QuestionStatus::Unattempted));
            continue;
        }
        // Retries already observe this interval inside the query engine.
        // Preserve it across question boundaries too; a batch must not turn
        // single-attempt questions into an unpaced burst.
        if let Some(previous) = previous_delay {
            let delay = previous.max(prepared.delay);
            if !delay.is_zero() {
                let mut pause = Context::new(&mut *deadline, &mut *clock, Attempts);
                let waited = pause.pace(FIRST_ATTEMPT, delay).and_then(|()| {
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
                            Question::ended(request, QuestionStatus::Unattempted)
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
            Ok(()) => questions.push(Question {
                result: Some(prepared.report),
                ..Question::ended(request, QuestionStatus::Completed)
            }),
            Err(error @ Error::Output { .. }) => return Err(error),
            Err(error) => {
                // A stop request or an exhausted shared deadline ends the
                // batch; remaining questions are unattempted, not failed.
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
