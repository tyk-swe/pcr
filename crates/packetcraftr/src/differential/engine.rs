// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::layer::Raw;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::Udp;
use packetcraftr_netio::capture::ObservationQuality;

use super::canary::{self, TOKEN_LEN};
use super::error::{Error, duration_limit};
use super::plan::{self, AttemptPlan, Prepared};
use super::report::{Event, Report, Verdict, rows_for};
use super::{AttemptEvidence, Request};
use crate::clock::Clock;
use crate::engine::execution::publisher;
use crate::engine::operation::Operation;
use crate::providers::PacketProviders;
use crate::route;
use crate::{Client, Sink, Stats};

fn reply_payload(decoded: &DecodedPacket) -> Option<Vec<u8>> {
    decoded
        .packet
        .iter()
        .last()
        .and_then(|layer| layer.downcast_ref::<Raw>())
        .map(|raw| raw.bytes.to_vec())
}

fn tuple_matches(request: &Packet, response: &DecodedPacket, target: Ipv4Addr) -> bool {
    let (Some(sent_udp), Some(ip), Some(udp)) = (
        request.get::<Udp>(),
        response.packet.get::<Ipv4>(),
        response.packet.get::<Udp>(),
    ) else {
        return false;
    };
    if ip.source != target || udp.destination_port != sent_udp.source_port {
        return false;
    }
    if udp.source_port != sent_udp.destination_port {
        return false;
    }
    match request.get::<Ipv4>() {
        Some(sent_ip) if !sent_ip.source.is_unspecified() => ip.destination == sent_ip.source,
        _ => true,
    }
}

fn matches_attempt(
    token: &[u8; TOKEN_LEN],
    target: Ipv4Addr,
    attempt: &AttemptPlan,
    request_index: usize,
    request: &Packet,
    response: &DecodedPacket,
) -> bool {
    if request_index != 0 || !tuple_matches(request, response, target) {
        return false;
    }
    let Some(bytes) = reply_payload(response) else {
        return false;
    };
    let Some(reply) = canary::parse_reply(&bytes) else {
        return false;
    };
    reply.token == *token
        && usize::from(reply.variant_index) == attempt.variant_index
        && reply.attempt_seq == attempt.attempt_seq
        && reply.received_payload_sha256 == attempt.payload_sha256
}

#[derive(Clone, Debug, Default)]
pub(super) struct AttemptOutcome {
    pub answered: bool,
    pub packets_sent: usize,
    pub reply: Option<Frame>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}

pub(super) trait Runner {
    fn run_attempt(
        &mut self,
        request: &Request,
        attempt: &AttemptPlan,
        spent: &Stats,
    ) -> Result<AttemptOutcome, Error>;
}

struct ClientRunner<'a, P, K> {
    client: &'a Client<P, K>,
    operation: &'a Operation,
    send: crate::send::Options,
    pinned: Option<route::Plan>,
}

impl<P: PacketProviders, K: Clock> Runner for ClientRunner<'_, P, K> {
    fn run_attempt(
        &mut self,
        request: &Request,
        attempt: &AttemptPlan,
        spent: &Stats,
    ) -> Result<AttemptOutcome, Error> {
        let mut step = self.operation.clone();
        step.spent = spent.clone();
        let token = request.token;
        let target = request.target;
        let attempt_seq = attempt.attempt_seq;
        let mut matcher = |request_index: usize, sent: &Packet, received: &DecodedPacket| {
            matches_attempt(&token, target, attempt, request_index, sent, received)
        };
        let evidence = self
            .client
            .exchange_packets(
                attempt.packets.clone(),
                &self.send,
                request.timeout,
                request.collection.clone(),
                &step,
                &mut matcher,
                &mut self.pinned,
            )
            .map_err(|source| Error::Execution {
                attempt: u64::from(attempt_seq),
                source: BoundaryError::from_error(source),
            })?;
        if evidence.observation_quality == ObservationQuality::Incomplete {
            return Err(Error::IncompleteEvidence {
                attempt: u64::from(attempt_seq),
            });
        }
        let aggregate = evidence.aggregate;
        let reply = aggregate
            .responses
            .first()
            .map(|response| response.response.frame.clone());
        Ok(AttemptOutcome {
            answered: !aggregate.responses.is_empty(),
            packets_sent: aggregate.sent.len(),
            reply,
            diagnostics: aggregate.diagnostics,
            stats: aggregate.stats,
        })
    }
}

pub(super) fn run_campaign<R: Runner>(
    request: &Request,
    prepared: &Prepared,
    runner: &mut R,
    deadline: &Deadline,
    mut publish: impl FnMut(Event, &Deadline) -> Result<(), Error>,
) -> Result<Report, Error> {
    let gate_on_baseline = request.spoof_source.is_none();
    let mut spent = Stats::default();
    let mut attempts: Vec<AttemptEvidence> = Vec::new();
    for plan_attempt in &prepared.attempts {
        deadline.check_cancelled().map_err(Error::from)?;
        let outcome = runner.run_attempt(request, plan_attempt, &spent)?;
        spent
            .checked_add_assign(&outcome.stats)
            .map_err(|_| Error::StatisticsOverflow)?;
        for diagnostic in outcome.diagnostics {
            publish(Event::Diagnostic(diagnostic), deadline)?;
        }
        let attempt = AttemptEvidence {
            variant_index: plan_attempt.variant_index,
            attempt_seq: plan_attempt.attempt_seq,
            answered: outcome.answered,
            packets_sent: outcome.packets_sent,
            payload_sha256: plan_attempt.payload_sha256,
            reply: outcome.reply,
        };
        let baseline_done = plan_attempt.variant_index == 0
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
            publish(Event::Attempt(last.clone()), deadline)?;
        }
        if gate_on_baseline && baseline_done && !baseline_answered {
            break;
        }
    }
    let rows = rows_for(&attempts);
    let valid = rows
        .first()
        .is_some_and(|row| row.verdict == Verdict::Accepted);
    Ok(Report {
        valid,
        provisional: request.spoof_source.is_some(),
        plan_digest: prepared.summary.digest.clone(),
        source_port: request.source_port,
        spoof_source: request.spoof_source,
        rows,
        stats: spent,
    })
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
        let publish = publisher(&self.runtime, sink, duration_limit, |source| {
            Error::Output { source }
        })?;
        let mut runner = ClientRunner {
            client: self,
            operation: &operation,
            send: request.send(),
            pinned: None,
        };
        run_campaign(&request, &prepared, &mut runner, &deadline, publish)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SystemProviders;
    use crate::differential::Collector;
    use crate::differential::catalog::catalog;
    use crate::policy::Policy;
    use packetcraftr_core::build::Builder;
    use packetcraftr_core::decode::Dissector;
    use packetcraftr_core::frame::{Frame, LinkType};
    use packetcraftr_core::layer::Raw;
    use packetcraftr_core::protocol::builtin;
    use std::collections::HashSet;
    use std::time::{Duration, SystemTime};

    fn client() -> Client<SystemProviders> {
        Client::new(builtin::registry(), Policy::default(), SystemProviders)
    }

    fn request() -> Request {
        let mut request = Request::new(Ipv4Addr::new(192, 0, 2, 10), 40101, [0x42; 16]);
        request.repeats = 2;
        request.payload_len = 256;
        request
    }

    struct FakeRunner {
        answered: HashSet<u32>,
        ran: Vec<u32>,
    }

    impl Runner for FakeRunner {
        fn run_attempt(
            &mut self,
            _request: &Request,
            attempt: &AttemptPlan,
            _spent: &Stats,
        ) -> Result<AttemptOutcome, Error> {
            self.ran.push(attempt.attempt_seq);
            Ok(AttemptOutcome {
                answered: self.answered.contains(&attempt.attempt_seq),
                packets_sent: attempt.packets.len(),
                ..AttemptOutcome::default()
            })
        }
    }

    fn campaign(request: &Request, runner: &mut FakeRunner) -> Report {
        let prepared = plan::prepare(&builtin::registry(), request).expect("plan prepares");
        run_campaign(
            request,
            &prepared,
            runner,
            &Deadline::new(Duration::from_secs(60)),
            |_event, _deadline| Ok(()),
        )
        .expect("campaign runs")
    }

    fn all_seqs(request: &Request) -> HashSet<u32> {
        (0..catalog().len() as u32 * request.repeats).collect()
    }

    #[test]
    fn completed_campaign_reports_accepted_rows() {
        let request = request();
        let mut runner = FakeRunner {
            answered: all_seqs(&request),
            ran: Vec::new(),
        };
        let report = campaign(&request, &mut runner);
        assert!(report.valid);
        assert_eq!(runner.ran.len(), catalog().len() * 2);
        assert!(
            report
                .rows
                .iter()
                .all(|row| row.verdict == Verdict::Accepted)
        );
    }

    #[test]
    fn baseline_gate_stops_an_unspoofed_campaign() {
        let request = request();
        let mut runner = FakeRunner {
            answered: HashSet::new(),
            ran: Vec::new(),
        };
        let report = campaign(&request, &mut runner);
        assert!(!report.valid);
        assert_eq!(runner.ran, vec![0, 1], "only baseline attempts may run");
        assert_eq!(report.rows[0].verdict, Verdict::Unanswered);
        assert_eq!(report.rows[1].verdict, Verdict::NotRun);
    }

    #[test]
    fn baseline_gate_is_deferred_for_spoofed_campaigns() {
        let mut request = request();
        request.spoof_source = Some(Ipv4Addr::new(192, 0, 2, 99));
        let mut runner = FakeRunner {
            answered: HashSet::new(),
            ran: Vec::new(),
        };
        let report = campaign(&request, &mut runner);
        assert!(report.provisional);
        assert_eq!(
            runner.ran.len(),
            catalog().len() * 2,
            "every attempt runs so the reception log can finalize them"
        );
    }

    #[test]
    fn mixed_answers_report_flaky_after_a_clean_baseline() {
        let request = request();
        let mut answered = all_seqs(&request);
        answered.remove(&3);
        let mut runner = FakeRunner {
            answered,
            ran: Vec::new(),
        };
        let report = campaign(&request, &mut runner);
        assert!(report.valid);
        assert_eq!(report.rows[1].verdict, Verdict::Flaky);
    }

    fn decode(packet: Packet) -> DecodedPacket {
        let built = Builder::new(builtin::registry())
            .build(packet, Default::default(), Default::default())
            .expect("packet builds");
        Dissector::new(builtin::registry())
            .decode(
                Frame::new(Some(SystemTime::now()), LinkType::RAW, built.bytes)
                    .expect("frame builds"),
                Default::default(),
            )
            .expect("packet dissects")
    }

    #[test]
    fn matcher_requires_the_responder_tuple() {
        let token = [0x42; TOKEN_LEN];
        let target = Ipv4Addr::new(192, 0, 2, 10);
        let payload = canary::build_probe(&token, 0, 0, 256);
        let probe = canary::parse_probe(&payload).expect("probe parses");
        let mut sent = Packet::default();
        sent.push(Ipv4 {
            destination: target,
            source: Ipv4Addr::new(192, 0, 2, 2),
            ..Ipv4::default()
        });
        sent.push(Udp {
            source_port: 53210,
            destination_port: 40101,
            ..Udp::default()
        });
        sent.push(Raw::new(payload.clone()));

        let reply_from = |source: Ipv4Addr, source_port: u16| {
            let mut packet = Packet::default();
            packet.push(Ipv4 {
                source,
                destination: Ipv4Addr::new(192, 0, 2, 2),
                ..Ipv4::default()
            });
            packet.push(Udp {
                source_port,
                destination_port: 53210,
                ..Udp::default()
            });
            packet.push(Raw::new(canary::build_reply(&probe)));
            decode(packet)
        };

        let attempt = AttemptPlan {
            variant_index: 0,
            attempt_seq: 0,
            packets: vec![sent.clone()],
            payload_sha256: probe.payload_sha256,
        };
        assert!(matches_attempt(
            &token,
            target,
            &attempt,
            0,
            &sent,
            &reply_from(target, 40101),
        ));
        assert!(!matches_attempt(
            &token,
            target,
            &attempt,
            0,
            &sent,
            &reply_from(Ipv4Addr::new(198, 51, 100, 7), 40101),
        ));
        assert!(!matches_attempt(
            &token,
            target,
            &attempt,
            0,
            &sent,
            &reply_from(target, 9999),
        ));
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
        assert_eq!(summary.rows.len(), catalog().len());
        assert!(summary.total_packets > 0);
    }
}
