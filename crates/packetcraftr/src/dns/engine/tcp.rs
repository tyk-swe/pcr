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
use crate::dns::tcp::Category as TcpCategory;
use crate::policy::Authorizer;
use crate::probe::Executor;
use crate::target::{Family, Target, resolve_selected};

use super::super::classification::{
    ClassifiedAttempt, classify_tcp_response, tcp_failure_evidence, tcp_timeout_evidence,
};
use super::super::error::Error;
use super::super::{Event, Exchange, Outcome, Probe, TcpExchange, TcpExecutor};
use super::{Gates, Operation};

impl<A, E, C, F> Operation<'_, A, E, C, F>
where
    A: Authorizer,
    E: Executor<Exchange> + TcpExecutor,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    pub(super) fn execute_tcp_query(
        &mut self,
        probe: &Probe,
        attempt_deadline: &mut Deadline,
    ) -> Result<ClassifiedAttempt, Error> {
        if !self.authorize_tcp_destination(probe, attempt_deadline)? {
            return Ok(tcp_timeout_evidence(
                probe,
                "the DNS attempt deadline expired before connection",
            ));
        }
        let mut exchange = TcpExchange {
            attempt: probe.attempt,
            endpoint: SocketAddr::new(probe.server_address, probe.server_port),
            query: probe.query.clone(),
            timeout: Duration::ZERO,
            max_message_bytes: self.request.limits.message.max_message_bytes,
            permit: crate::evidence::ExecutionPermit::new(),
        };
        self.execution
            .deadline_mut()
            .start_accounting(Duration::ZERO)?;
        if attempt_deadline.start_accounting(Duration::ZERO).is_err() {
            return Ok(tcp_timeout_evidence(
                probe,
                "the DNS attempt deadline expired before connection",
            ));
        }
        let timeout = attempt_deadline
            .remaining()
            .map_err(|_| Error::InvalidEvidence {
                attempt: probe.attempt,
                message: "shared DNS attempt deadline regressed after accounting".to_owned(),
            })?
            .min(self.execution.deadline().remaining()?);
        if timeout.is_zero() {
            return Ok(tcp_timeout_evidence(
                probe,
                "the DNS attempt deadline expired before connection",
            ));
        }
        exchange.timeout = timeout;
        let boundary_started = Instant::now();
        let result = self.executor.execute_tcp(&exchange);
        let boundary_elapsed = boundary_started.elapsed();
        if let Ok(execution) = &result
            && execution.permit != exchange.permit
        {
            return Err(Error::InvalidEvidence {
                attempt: probe.attempt,
                message: "TCP executor returned evidence for a different execution permit"
                    .to_owned(),
            });
        }
        let reported_elapsed = result
            .as_ref()
            .map_or(boundary_elapsed, |execution| execution.response.elapsed);
        let mut tcp_stats = Stats {
            elapsed: reported_elapsed,
            ..Stats::default()
        };
        let framed_query_bytes =
            probe
                .query
                .len()
                .checked_add(2)
                .ok_or(Error::InvalidEvidence {
                    attempt: probe.attempt,
                    message: "TCP query length accounting overflowed".to_owned(),
                })?;
        let bytes_written = match &result {
            Ok(execution) => execution.response.bytes_written,
            Err(error) => error.query_bytes_written(framed_query_bytes),
        };
        if bytes_written > framed_query_bytes {
            return Err(Error::InvalidEvidence {
                attempt: probe.attempt,
                message: "TCP executor reported more query bytes than were authorized".to_owned(),
            });
        }
        tcp_stats.bytes = u64::try_from(bytes_written).unwrap_or(u64::MAX);
        self.execution.merge(probe.attempt, &tcp_stats)?;

        self.execution.deadline().check_cancelled()?;
        self.execution.deadline_mut().account(reported_elapsed)?;
        let attempt_expired = attempt_deadline.account(reported_elapsed).is_err();

        if attempt_expired || reported_elapsed > timeout {
            return Ok(tcp_timeout_evidence(
                probe,
                "DNS-over-TCP did not complete within the shared attempt deadline",
            ));
        }
        let error = match result {
            Ok(execution) => {
                return classify_tcp_response(
                    probe,
                    timeout,
                    execution.response,
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
            _ => Err(Error::InvalidEvidence {
                attempt: probe.attempt,
                message: format!("TCP executor rejected the validated local request: {error}"),
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
            &Gates,
        );
        self.execution.enforce(probe.attempt)?;
        if attempt_deadline.check().is_err() {
            return Ok(false);
        }
        let resolved = resolved?;
        if resolved.addresses.as_slice() != [probe.server_address] {
            return Err(Error::InvalidEvidence {
                attempt: probe.attempt,
                message: format!(
                    "TCP destination reauthorization did not preserve selected server {}",
                    probe.server_address
                ),
            });
        }
        Ok(true)
    }
}
