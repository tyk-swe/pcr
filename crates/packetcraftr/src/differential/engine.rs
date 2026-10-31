// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::layer::Raw;
use packetcraftr_core::packet::Packet;

use super::canary::{self, TOKEN_LEN};
use super::error::{Error, duration_limit};
use super::plan;
use super::report::{Event, Report, Verdict, rows_for};
use super::{AttemptEvidence, Request};
use crate::clock::Clock;
use crate::engine::execution::publisher;
use crate::engine::operation::Operation;
use crate::providers::PacketProviders;
use crate::{Client, Sink, Stats};

fn reply_payload(decoded: &DecodedPacket) -> Option<Vec<u8>> {
    decoded
        .packet
        .iter()
        .last()
        .and_then(|layer| layer.downcast_ref::<Raw>())
        .map(|raw| raw.bytes.to_vec())
}

fn matches_attempt(
    token: &[u8; TOKEN_LEN],
    variant_index: usize,
    attempt_seq: u32,
    payload_sha256: &[u8; 32],
    request_index: usize,
    _request: &Packet,
    response: &DecodedPacket,
) -> bool {
    if request_index != 0 {
        return false;
    }
    let Some(bytes) = reply_payload(response) else {
        return false;
    };
    let Some(reply) = canary::parse_reply(&bytes) else {
        return false;
    };
    reply.token == *token
        && usize::from(reply.variant_index) == variant_index
        && reply.attempt_seq == attempt_seq
        && reply.received_payload_sha256 == *payload_sha256
}

impl<P: PacketProviders, K: Clock> Client<P, K> {
    pub fn differential_plan(&self, request: Request) -> Result<plan::PlanSummary, Error> {
        request.validate()?;
        let prepared = plan::prepare(&self.registry, &request)?;
        plan::authorize(&self.policy, &request, &prepared)?;
        Ok(prepared.summary)
    }

    pub fn differential<S>(&self, request: Request, sink: S) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        request.validate()?;
        let presented = request
            .plan_digest
            .clone()
            .ok_or(Error::PlanDigestMissing)?;
        let prepared = plan::prepare(&self.registry, &request)?;
        if presented != prepared.summary.digest {
            return Err(Error::PlanDigestMismatch {
                expected: prepared.summary.digest.clone(),
                presented,
            });
        }
        plan::authorize(&self.policy, &request, &prepared)?;

        let operation = Operation::new(self, request.max_duration);
        let deadline = operation.deadline(self, request.max_duration);
        let mut publish = publisher(&self.runtime, sink, duration_limit, |source| {
            Error::Output { source }
        })?;
        let send = request.send();
        let mut pinned = None;
        let mut spent = Stats::default();
        let mut attempts: Vec<AttemptEvidence> = Vec::new();
        let mut baseline_failed = false;

        for plan_attempt in &prepared.attempts {
            if baseline_failed {
                break;
            }
            deadline.check_cancelled().map_err(Error::from)?;
            let mut step = operation.clone();
            step.spent = spent.clone();
            let token = request.token;
            let variant_index = plan_attempt.variant_index;
            let attempt_seq = plan_attempt.attempt_seq;
            let payload_sha256 = plan_attempt.payload_sha256;
            let mut matcher = |request_index: usize, sent: &Packet, received: &DecodedPacket| {
                matches_attempt(
                    &token,
                    variant_index,
                    attempt_seq,
                    &payload_sha256,
                    request_index,
                    sent,
                    received,
                )
            };
            let evidence = self
                .exchange_packets(
                    plan_attempt.packets.clone(),
                    &send,
                    request.timeout,
                    request.collection.clone(),
                    &step,
                    &mut matcher,
                    &mut pinned,
                )
                .map_err(|source| Error::Execution {
                    attempt: u64::from(attempt_seq),
                    source: BoundaryError::from_error(source),
                })?;
            let aggregate = evidence.aggregate;
            spent
                .checked_add_assign(&aggregate.stats)
                .map_err(|_| Error::StatisticsOverflow)?;
            let reply = aggregate
                .responses
                .first()
                .map(|response| response.response.frame.clone());
            let attempt = AttemptEvidence {
                variant_index,
                attempt_seq,
                answered: !aggregate.responses.is_empty(),
                packets_sent: aggregate.sent.len(),
                payload_sha256,
                reply,
            };
            for diagnostic in aggregate.diagnostics {
                publish(Event::Diagnostic(diagnostic), &deadline)?;
            }
            let is_last_baseline_attempt = variant_index == 0
                && attempts
                    .iter()
                    .filter(|done| done.variant_index == 0)
                    .count()
                    + 1
                    == request.repeats as usize;
            let baseline_answered = attempt.answered
                && attempts
                    .iter()
                    .filter(|done| done.variant_index == 0)
                    .all(|done| done.answered);
            attempts.push(attempt);
            if let Some(last) = attempts.last() {
                publish(Event::Attempt(last.clone()), &deadline)?;
            }
            if is_last_baseline_attempt && !baseline_answered {
                baseline_failed = true;
            }
        }

        let rows = rows_for(&attempts);
        let valid = rows
            .first()
            .is_some_and(|row| row.verdict == Verdict::Accepted);
        Ok(Report {
            valid,
            provisional: request.spoof_source.is_some(),
            plan_digest: prepared.summary.digest,
            rows,
            stats: spent,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SystemProviders;
    use crate::differential::Collector;
    use crate::policy::Policy;
    use packetcraftr_core::protocol::builtin;
    use std::net::Ipv4Addr;

    fn client() -> Client<SystemProviders> {
        Client::new(builtin::registry(), Policy::default(), SystemProviders)
    }

    fn request() -> Request {
        Request::new(Ipv4Addr::new(192, 0, 2, 10), 40101, [0x42; 16])
    }

    #[test]
    fn live_run_without_digest_is_refused_before_any_send() {
        let outcome = client().differential(request(), Collector::default());
        assert!(matches!(outcome, Err(Error::PlanDigestMissing)));
    }

    #[test]
    fn live_run_with_wrong_digest_is_refused_before_any_send() {
        let mut request = request();
        request.plan_digest = Some("not-the-plan-digest".to_owned());
        let outcome = client().differential(request, Collector::default());
        assert!(matches!(outcome, Err(Error::PlanDigestMismatch { .. })));
    }

    #[test]
    fn plan_only_run_returns_a_digest_without_sending() {
        let summary = client()
            .differential_plan(request())
            .expect("documentation-range plan authorizes");
        assert_eq!(summary.digest.len(), 64);
        assert_eq!(
            summary.rows.len(),
            crate::differential::catalog::catalog().len()
        );
        assert!(summary.total_packets > 0);
    }
}
