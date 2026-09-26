// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded multi-question DNS batches under one operation deadline.

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::registry::Registry;

use crate::clock::Clock;
use crate::execution::Context;
use crate::execution::Executor;
use crate::execution::sink_observer;
use crate::policy::{Authorizer, Operation};
use crate::progress::Runtime;
use crate::target::approve_operation;
use crate::{BoundaryError, Stats};

use super::engine::{Attempts, PreparedOperation};
use super::plan::batch_limits;
use super::report::{Collector, Report};
use super::{Error, Event, Request};

pub const MAX_QUESTIONS: usize = 256;

/// How one batch question ended, in the request's declared order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionStatus {
    /// The question ran to completion; `report` carries its evidence and the
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

/// The deterministic outcome of one batch question, in input order.
#[derive(Debug)]
pub struct QuestionOutcome {
    pub query_name: String,
    pub query_type: super::QueryType,
    pub transaction_id: u16,
    pub status: QuestionStatus,
    /// The collected report; present exactly when `status` is
    /// [`QuestionStatus::Completed`].
    pub report: Option<Report>,
    /// The classified failure; present exactly when `status` is
    /// [`QuestionStatus::Failed`].
    pub error: Option<Error>,
}

/// The complete batch outcome: one entry per declared question, in input
/// order, plus the exact totals confirmed across all questions.
#[derive(Debug)]
pub struct BatchReport {
    /// The server target every question shared, exactly as declared.
    pub server: String,
    pub server_port: u16,
    pub questions: Vec<QuestionOutcome>,
    pub stats: Stats,
}

impl BatchReport {
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

/// Runs requests in input order under the minimum `limits.max_duration` in the
/// batch.
///
/// Prepares and authorizes the combined worst-case traffic limits before
/// discovery. Cancellation or deadline exhaustion leaves remaining questions
/// [`QuestionStatus::Unattempted`]; other question failures are
/// [`QuestionStatus::Failed`] and allow the batch to continue. Output failures
/// stop execution immediately.
pub fn run_batch<A, E, C>(
    requests: &[Request],
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
) -> Result<BatchReport, Error>
where
    A: Authorizer,
    E: Executor<super::Exchange> + super::TcpExecutor,
    C: Clock,
{
    let mut deadline = batch_deadline(requests)?.with_cancellation(clock.cancellation());
    run_batch_observed(
        requests,
        authorizer,
        registry,
        executor,
        clock,
        &mut deadline,
        |event, _| {
            let _ = event;
            Ok(())
        },
    )
}

/// [`run_batch`] with progressive per-question events on a runtime-budgeted
/// publisher, matching [`run_with_events`](super::run_with_events) semantics.
pub fn run_batch_with_events<A, E, C, F>(
    requests: &[Request],
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    runtime: &Runtime,
    emit: F,
) -> Result<BatchReport, Error>
where
    A: Authorizer,
    E: Executor<super::Exchange> + super::TcpExecutor,
    C: Clock,
    F: FnMut(Event) -> Result<(), BoundaryError> + Send + 'static,
{
    let observe = sink_observer(runtime, emit, Error::from, |source| Error::Output {
        source,
    })?;
    let mut deadline = batch_deadline(requests)?.with_cancellation(clock.cancellation());
    run_batch_observed(
        requests,
        authorizer,
        registry,
        executor,
        clock,
        &mut deadline,
        observe,
    )
}

fn validate_batch(requests: &[Request]) -> Result<(), Error> {
    if requests.is_empty() || requests.len() > MAX_QUESTIONS {
        return Err(Error::InvalidLimit {
            field: "questions",
            value: requests.len() as u64,
            reason: format!("must be within 1..={MAX_QUESTIONS}"),
        });
    }
    let first = &requests[0];
    if let Some(index) = requests.iter().position(|request| {
        request.server != first.server || request.server_port != first.server_port
    }) {
        return Err(Error::InvalidLimit {
            field: "questions",
            value: index as u64,
            reason: "all questions must share the same server and server port".to_owned(),
        });
    }
    Ok(())
}

fn batch_deadline(requests: &[Request]) -> Result<Deadline, Error> {
    validate_batch(requests)?;
    Ok(Deadline::new(
        requests
            .iter()
            .map(|request| request.limits.max_duration)
            .min()
            .expect("a non-empty batch has a minimum"),
    ))
}

/// The wait between questions precedes the next question's first attempt,
/// so its failures name that attempt.
const FIRST_ATTEMPT: u32 = 1;

pub(super) fn run_batch_observed<A, E, C, F>(
    requests: &[Request],
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    deadline: &mut Deadline,
    mut observe: F,
) -> Result<BatchReport, Error>
where
    A: Authorizer,
    E: Executor<super::Exchange> + super::TcpExecutor,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    validate_batch(requests)?;
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
    let mut previous_delay: Option<std::time::Duration> = None;
    for (request, mut prepared) in requests.iter().zip(prepared) {
        // Cancellation wins over elapsed-time reporting, matching every other
        // deadline gate.
        if stop || deadline.enforce().is_err() {
            questions.push(unattempted(request));
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
                        Error::Cancelled(_) | Error::DurationLimit { .. } => unattempted(request),
                        error => failed(request, error),
                    });
                    continue;
                }
            }
        }
        previous_delay = Some(prepared.delay);
        let mut collector = Collector::default();
        let result = prepared.execute(
            authorizer,
            registry,
            executor,
            clock,
            &mut *deadline,
            |event, deadline| {
                collector.observe(event.clone());
                observe(event, deadline)
            },
        );
        stats
            .checked_add_assign(&prepared.summary.stats)
            .map_err(|_| Error::StatisticsOverflow {
                attempt: request.attempts,
            })?;
        match result {
            Ok(()) => match collector.finish(prepared.summary) {
                Ok(report) => {
                    questions.push(QuestionOutcome {
                        query_name: request.query_name.clone(),
                        query_type: request.query_type,
                        transaction_id: request.transaction_id,
                        status: QuestionStatus::Completed,
                        report: Some(report),
                        error: None,
                    });
                }
                Err(error) => questions.push(failed(request, error)),
            },
            Err(error @ Error::Output { .. }) => return Err(error),
            Err(error) => {
                // A stop request or an exhausted shared deadline ends the
                // batch; remaining questions are unattempted, not failed.
                stop = matches!(error, Error::Cancelled(_) | Error::DurationLimit { .. });
                questions.push(failed(request, error));
            }
        }
    }
    Ok(BatchReport {
        server: requests[0].server.to_string(),
        server_port: requests[0].server_port,
        questions,
        stats,
    })
}

fn unattempted(request: &Request) -> QuestionOutcome {
    QuestionOutcome {
        query_name: request.query_name.clone(),
        query_type: request.query_type,
        transaction_id: request.transaction_id,
        status: QuestionStatus::Unattempted,
        report: None,
        error: None,
    }
}

fn failed(request: &Request, error: Error) -> QuestionOutcome {
    QuestionOutcome {
        query_name: request.query_name.clone(),
        query_type: request.query_type,
        transaction_id: request.transaction_id,
        status: QuestionStatus::Failed,
        report: None,
        error: Some(error),
    }
}
