// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS-over-TCP attempt authorization, execution, evidence validation, and
//! accounting. The parent engine owns retries, fallback, transport selection,
//! and event ordering.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use packetcraftr_core::budget::Deadline;

use crate::Stats;
use crate::clock::Clock;
use crate::dns::tcp::{Category as TcpCategory, Error as TcpError};
use crate::evidence::ExecutionPermit;
use crate::execution::Executor;
use crate::execution::Receipt;
use crate::policy::Authorizer;
use crate::target::ResolveTarget;
use crate::target::{Family, Target, resolve_selected};

use super::super::classification::{
    ClassifiedAttempt, classify_tcp_response, tcp_failure_evidence, tcp_timeout_evidence,
};
use super::super::error::{Error, EvidenceFault};
use super::super::executor::{Exchange, TcpEvidence, TcpQuerier, TcpQuery};
use super::super::probe::Probe;
use super::super::{Event, Outcome};
use super::{Attempts, Retries};

impl<A, E, C, F> Retries<'_, A, E, C, F>
where
    A: Authorizer + ResolveTarget,
    E: Executor<Exchange> + TcpQuerier,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    pub(super) fn execute_tcp_query(
        &mut self,
        probe: &Probe,
        attempt_deadline: &mut Deadline,
    ) -> Result<ClassifiedAttempt, Error> {
        if !self.authorize_tcp_destination(probe, attempt_deadline)? {
            return Ok(expired_before_connection(probe));
        }
        // The attempt window is DNS's own; what it has left is the timeout
        // this step requests from the execution context.
        if attempt_deadline.start_accounting(Duration::ZERO).is_err() {
            return Ok(expired_before_connection(probe));
        }
        let requested = attempt_deadline
            .remaining()
            .map_err(|_| Error::InvalidEvidence {
                attempt: probe.attempt,
                fault: EvidenceFault::AttemptDeadlineRegressed,
            })?;
        if requested.is_zero() {
            return Ok(expired_before_connection(probe));
        }
        let framed_query_bytes =
            probe
                .query
                .len()
                .checked_add(2)
                .ok_or(Error::InvalidEvidence {
                    attempt: probe.attempt,
                    fault: EvidenceFault::TcpQueryLengthOverflow,
                })?;
        let max_message_bytes = self.request.limits.message.max_message_bytes;
        let (attempt, grant) = self.execution.step(
            probe.attempt,
            requested,
            &mut *self.executor,
            |executor, grant| {
                let query = TcpQuery {
                    attempt: probe.attempt,
                    endpoint: SocketAddr::new(probe.server_address, probe.server_port),
                    query: probe.query.clone(),
                    timeout: grant.timeout,
                    max_message_bytes,
                    permit: grant.permit,
                };
                Ok(TcpAttempt::execute(executor, &query, framed_query_bytes))
            },
            |_, attempt, _, _| {
                if attempt.bytes_written > framed_query_bytes {
                    return Err(Error::InvalidEvidence {
                        attempt: probe.attempt,
                        fault: EvidenceFault::TcpBytesUnauthorized,
                    });
                }
                Ok(())
            },
        )?;
        let timeout = grant.timeout;
        let reported_elapsed = attempt.stats.elapsed;
        let attempt_expired = attempt_deadline.account(reported_elapsed).is_err();

        if attempt_expired || reported_elapsed > timeout {
            return Ok(tcp_timeout_evidence(
                probe,
                "DNS-over-TCP did not complete within the shared attempt deadline",
            ));
        }
        let error = match attempt.result {
            Ok(evidence) => {
                return classify_tcp_response(
                    probe,
                    timeout,
                    evidence.response,
                    self.request.limits.message,
                );
            }
            Err(error) => error,
        };
        match error.category() {
            TcpCategory::Timeout => Ok(tcp_failure_evidence(
                probe,
                Outcome::Timeout,
                error.to_string(),
            )),
            TcpCategory::Network => Ok(tcp_failure_evidence(
                probe,
                Outcome::NetworkFailure,
                error.to_string(),
            )),
            TcpCategory::Framing => Ok(tcp_failure_evidence(
                probe,
                Outcome::DecodeFailure,
                error.to_string(),
            )),
            TcpCategory::Unsupported => Err(Error::TcpExecution {
                attempt: probe.attempt,
                source: error,
            }),
            // `Request` — and any class added later — fails closed here: a
            // request this workflow built itself cannot be rejected by the
            // executor, so it is never a retryable per-attempt outcome.
            _ => Err(Error::TcpRequestRejected {
                attempt: probe.attempt,
                source: error,
            }),
        }
    }

    fn authorize_tcp_destination(
        &mut self,
        probe: &Probe,
        attempt_deadline: &Deadline,
    ) -> Result<bool, Error> {
        if attempt_deadline.check().is_err() {
            return Ok(false);
        }
        let target = Target::Address(probe.server_address);
        let resolved = resolve_selected(
            self.authorizer,
            &target,
            Family::Any,
            self.execution.deadline(),
            &Attempts,
        );
        self.execution.enforce(probe.attempt)?;
        if attempt_deadline.check().is_err() {
            return Ok(false);
        }
        let resolved = resolved?;
        if resolved.addresses.as_slice() != [probe.server_address] {
            return Err(Error::InvalidEvidence {
                attempt: probe.attempt,
                fault: EvidenceFault::TcpServerChanged {
                    server: probe.server_address,
                },
            });
        }
        Ok(true)
    }
}

fn expired_before_connection(probe: &Probe) -> ClassifiedAttempt {
    tcp_timeout_evidence(probe, "the DNS attempt deadline expired before connection")
}

/// One DNS-over-TCP execution as the execution context sees it. Socket and
/// framing failures are the executor's typed data, not a boundary failure, so
/// they are carried here with the traffic they may already have produced.
struct TcpAttempt {
    result: Result<TcpEvidence, TcpError>,
    permit: ExecutionPermit,
    bytes_written: usize,
    stats: Stats,
}

impl TcpAttempt {
    fn execute<E: TcpQuerier>(
        executor: &mut E,
        query: &TcpQuery,
        framed_query_bytes: usize,
    ) -> Self {
        let started = Instant::now();
        let result = executor.query(query);
        let boundary_elapsed = started.elapsed();
        let (permit, elapsed, bytes_written) = match &result {
            Ok(evidence) => (
                evidence.permit,
                evidence.response.elapsed,
                evidence.response.bytes_written,
            ),
            // A failure carries no evidence to bind to another permit.
            Err(error) => (
                query.permit,
                boundary_elapsed,
                error.query_bytes_written(framed_query_bytes),
            ),
        };
        Self {
            result,
            permit,
            bytes_written,
            stats: Stats {
                elapsed,
                bytes: u64::try_from(bytes_written).unwrap_or(u64::MAX),
                ..Stats::default()
            },
        }
    }
}

impl Receipt for TcpAttempt {
    fn permit(&self) -> ExecutionPermit {
        self.permit
    }

    fn stats(&self) -> &Stats {
        &self.stats
    }
}
