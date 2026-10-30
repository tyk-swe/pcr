// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::evidence::response::Passed;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use packetcraftr_core::{
    decode::DecodedPacket, diagnostic::Diagnostic, frame::Frame, packet::Packet,
    protocol::transport::Tcp, registry::Registry,
};

use super::plan::packet::sent_probe_matches;
use super::profile;
use super::report::RttAccumulator;
use super::{Classification, Event, Probe, ProbeEvidence, Reply, SctpScan, Stage, TcpScan};
use crate::engine::correlation::Correlation;
use crate::evidence::SentPacket;
use crate::probe;
use crate::probe::Transport;
use crate::probe::runner::{Classifier, NO_RESPONSE_REASON, Outcome};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorrelatedResponse {
    pub classification: Classification,
    pub reply: Reply,
    pub responder: IpAddr,
    pub reason: &'static str,
}

/// Classifies a valid correlated response; corrupt, unrelated, or inconsistent
/// responses return `None`.
pub fn classify_response(
    registry: &Registry,
    transport: Transport,
    request: &Packet,
    response: &DecodedPacket,
) -> Option<CorrelatedResponse> {
    let observation = crate::engine::correlation::observe(registry, transport, request, response)?;
    let classification = match observation.correlation {
        Correlation::TcpReset
        | Correlation::SctpAbort
        | Correlation::PortUnreachable
        | Correlation::ProtocolUnreachable => Classification::Closed,
        Correlation::TcpSynAck
        | Correlation::UdpReply
        | Correlation::SctpInitAck
        | Correlation::IcmpReply
        | Correlation::IcmpTimestampReply
        | Correlation::IcmpNetmaskReply
        | Correlation::IpProtocolReply => Classification::Open,
        Correlation::TcpOther | Correlation::SctpOther => Classification::Unknown,
        Correlation::TimeExceeded | Correlation::AdministrativelyProhibited => {
            Classification::Filtered
        }
        Correlation::DestinationUnreachable => Classification::Unreachable,
    };
    Some(CorrelatedResponse {
        classification,
        reply: Reply::from_correlation(observation.correlation),
        responder: observation.responder,
        reason: observation.reason,
    })
}

/// Diagnostic segments never claim a port open, and only the reset-based
/// FIN-family modes claim it closed; every other reply is uninterpreted.
fn diagnostic_classification(
    mode: TcpScan,
    reply: Reply,
    classified: Classification,
) -> Classification {
    match reply {
        Reply::TcpReset => match mode {
            TcpScan::Fin | TcpScan::Null | TcpScan::Xmas | TcpScan::Maimon => {
                Classification::Closed
            }
            _ => Classification::Unknown,
        },
        Reply::TcpSynAck | Reply::TcpOther => Classification::Unknown,
        Reply::IcmpPortUnreachable => Classification::Unreachable,
        _ => classified,
    }
}

fn sctp_cookie_echo_classification(reply: Reply, classified: Classification) -> Classification {
    match reply {
        Reply::SctpAbort => Classification::Closed,
        Reply::SctpInitAck | Reply::SctpOther => Classification::Unknown,
        Reply::IcmpPortUnreachable | Reply::IcmpProtocolUnreachable => Classification::Unreachable,
        _ => classified,
    }
}

/// A reset or abort from the endpoint outranks router evidence, which outranks
/// an uninterpreted segment, whatever the attempt classification says.
const fn diagnostic_rank(reply: Reply) -> u8 {
    match reply {
        Reply::TcpReset | Reply::SctpAbort => 5,
        Reply::IcmpPortUnreachable
        | Reply::IcmpProtocolUnreachable
        | Reply::IcmpAdministrativelyProhibited
        | Reply::IcmpDestinationUnreachable => 4,
        Reply::IcmpTimeExceeded => 3,
        _ => 2,
    }
}

pub(super) struct Observation {
    pub(super) response: CorrelatedResponse,
    pub(super) tcp_window: Option<u16>,
    pub(super) application: Option<profile::Evidence>,
    /// Transport response priority among replies to one probe (the
    /// application tie-break applies within it), independent of the attempt
    /// classification.
    transport_rank: u8,
}

impl Observation {
    pub(super) fn observe(
        registry: &Registry,
        probe: &Probe,
        sent: &Packet,
        response: &DecodedPacket,
    ) -> Option<Self> {
        let mut classified =
            classify_response(registry, probe.endpoint.transport(), sent, response)?;
        let tcp_diagnostic = probe.endpoint.transport() == Transport::Tcp
            && probe.stage == Stage::Scan
            && !probe.tcp_scan.is_syn();
        let sctp_cookie_echo = probe.endpoint.transport() == Transport::Sctp
            && probe.stage == Stage::Scan
            && probe.sctp_scan == SctpScan::CookieEcho;
        let tcp_window = if matches!(
            classified.reply,
            Reply::TcpSynAck | Reply::TcpReset | Reply::TcpOther
        ) {
            response.packet.get::<Tcp>().map(|tcp| tcp.window)
        } else {
            None
        };
        let transport_rank = if tcp_diagnostic || sctp_cookie_echo {
            diagnostic_rank(classified.reply)
        } else {
            classified.classification.rank()
        };
        if tcp_diagnostic {
            classified.classification = diagnostic_classification(
                probe.tcp_scan,
                classified.reply,
                classified.classification,
            );
        } else if sctp_cookie_echo {
            classified.classification =
                sctp_cookie_echo_classification(classified.reply, classified.classification);
        }
        Some(Self {
            response: classified,
            tcp_window,
            transport_rank,
            application: profile::evidence(probe, sent, response),
        })
    }

    /// Transport response priority decides first; application evidence
    /// breaks ties within that priority, and an unprofiled response
    /// ranks between failed and confirmed application evidence.
    pub(super) fn rank(&self) -> u8 {
        self.transport_rank * 4 + self.application.as_ref().map_or(2, profile::Evidence::rank)
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Feedback {
    pub(super) sequence: u64,
    pub(super) latency: Duration,
    pub(super) reply: Reply,
    pub(super) responder: IpAddr,
    pub(super) received_at: Option<SystemTime>,
}

pub(super) struct ProbeClassifier<'a> {
    pub(super) observation_quality: Option<packetcraftr_netio::capture::ObservationQuality>,
    pub(super) registry: &'a Registry,
    pub(super) target: Arc<str>,
    pub(super) winners: HashMap<super::report::WinnerKey, Classification>,
    pub(super) rtt: RttAccumulator,
    /// Discovery outcomes not yet composed into host records.
    pub(super) discovery: Vec<super::discovery::Observation>,
    pub(super) feedback: Option<(Vec<Feedback>, usize)>,
    pub(super) adaptive_attempts: Option<u32>,
}

impl Classifier for ProbeClassifier<'_> {
    type Probe = Probe;
    type Observation = Observation;
    type Event = Event;

    fn observation_quality(
        &mut self,
        quality: Option<packetcraftr_netio::capture::ObservationQuality>,
    ) {
        self.observation_quality = quality;
    }

    fn sent_matches(&self, probe: &Probe, sent: &Packet) -> bool {
        sent_probe_matches(probe, sent)
    }

    fn classify(
        &self,
        probe: &Probe,
        sent: &SentPacket,
        response: &DecodedPacket,
    ) -> Option<Observation> {
        Observation::observe(self.registry, probe, &sent.built().packet, response)
    }

    fn rank(&self, observation: &Observation) -> u8 {
        observation.rank()
    }

    fn responder(&self, observation: &Observation) -> IpAddr {
        observation.response.responder
    }

    fn canceled_responses(&self, probe: &Probe, outcome: &Outcome<Self::Observation>) -> usize {
        let Some(max_attempts) = self.adaptive_attempts else {
            return 0;
        };
        if !matches!(outcome, Outcome::Reply(_)) {
            return 0;
        }
        usize::try_from(max_attempts.saturating_sub(probe.attempt)).unwrap_or(0)
    }

    fn evidence(
        &mut self,
        probe: &Probe,
        sent: &SentPacket,
        outcome: Outcome<Observation>,
    ) -> Event {
        let mut evidence = ProbeEvidence {
            sequence: probe.sequence,
            measurement: super::Measurement::NoReply(
                self.observation_quality
                    .map_or(super::Coverage::Pending, Into::into),
            ),
            stage: probe.stage,
            address: probe.address,
            scope: probe.scope.clone(),
            endpoint: probe.endpoint,
            tcp_scan: (probe.endpoint.transport() == Transport::Tcp).then_some(probe.tcp_scan),
            sctp_scan: (probe.endpoint.transport() == Transport::Sctp).then_some(probe.sctp_scan),
            tcp_window: None,
            attempt: probe.attempt,
            status: probe::Status::Timeout,
            classification: Classification::Timeout,
            reply: None,
            responder: None,
            sent_at: sent.timing().freshness_marker().wall_clock(),
            received_at: None,
            latency: None,
            response: None,
            reason: NO_RESPONSE_REASON.to_owned(),
            application: probe
                .udp_profile
                .as_ref()
                .map(|profile| profile.not_observed()),
        };
        self.rtt.note_sent();
        if let Outcome::Reply(reply) = &outcome
            && let Some((feedback, cap)) = &mut self.feedback
            && feedback.len() < *cap
        {
            feedback.push(Feedback {
                sequence: probe.sequence,
                latency: reply.latency,
                reply: reply.observation.response.reply,
                responder: reply.observation.response.responder,
                received_at: reply.received_at,
            });
        }
        if let Outcome::Reply(reply) = outcome {
            self.rtt.note_received(reply.latency);
            evidence.status = probe::Status::Response;
            evidence.classification = reply.observation.response.classification;
            evidence.reply = Some(reply.observation.response.reply);
            evidence.measurement = super::Measurement::Response(reply.observation.response.reply);
            evidence.responder = Some(reply.observation.response.responder);
            evidence.received_at = reply.received_at;
            evidence.latency = Some(reply.latency);
            evidence.response = reply.frame;
            evidence.reason = reply.observation.response.reason.to_owned();
            evidence.application = reply.observation.application;
            evidence.tcp_window = reply.observation.tcp_window;
        }
        if let super::Measurement::NoReply(coverage) = evidence.measurement {
            self.rtt.note_no_reply(coverage);
        }
        match probe.stage {
            Stage::Scan => self
                .winners
                .entry((
                    evidence.address,
                    evidence.endpoint.transport(),
                    evidence.endpoint.port(),
                    evidence.endpoint.ip_protocol(),
                    evidence.scope.as_ref().map(|scope| scope.interface.clone()),
                ))
                .or_insert(Classification::Timeout)
                .promote(evidence.classification),
            Stage::Discovery => self.discovery.push(super::discovery::Observation {
                sequence: evidence.sequence,
                address: evidence.address,
                interface: evidence.scope.as_ref().map(|scope| scope.interface.clone()),
                response: evidence
                    .reply
                    .zip(evidence.responder)
                    .map(|(reply, responder)| {
                        (super::discovery::ReasonKind::Reply(reply), responder)
                    }),
                // Validation rejects a matched reply without a capture
                // timestamp, so only a probe with no reply, which yields no
                // reason, falls back to its send time.
                observed_at: evidence.received_at.unwrap_or(evidence.sent_at),
            }),
        }
        Event::Probe {
            target: Arc::clone(&self.target),
            probe: evidence,
        }
    }

    fn undecoded(&self, _probes: &[Probe], frame: Frame) -> Event {
        Event::Undecoded { frame }
    }

    fn passed(&self, probe: &Probe, passed: Passed, frame: Frame) -> Option<Event> {
        Some(Event::Unattributed(super::Unattributed {
            attribution: match passed {
                Passed::Late => super::Attribution::Late,
                Passed::Superseded => super::Attribution::Duplicate,
            },
            sequence: Some(probe.sequence),
            frame,
        }))
    }

    fn unsolicited(
        &self,
        probe: &Probe,
        sent: &SentPacket,
        capture: &crate::probe::runner::UnsolicitedCapture,
        has_response: bool,
    ) -> Option<Event> {
        let received_at = capture.received_at?;
        if received_at < sent.timing().freshness_marker().monotonic() {
            return None;
        }
        self.classify(probe, sent, &capture.decoded)?;
        let passed = if capture.correlation_expired
            || received_at > capture.response_deadline
            || !has_response
        {
            Passed::Late
        } else {
            Passed::Superseded
        };
        self.passed(probe, passed, capture.decoded.frame.clone())
    }

    fn diagnostic(&self, diagnostic: Diagnostic) -> Event {
        Event::Diagnostic(diagnostic)
    }
}
