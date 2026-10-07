// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::execution::evidence::Passed;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use packetcraftr_core::{
    decode::DecodedPacket, diagnostic::Diagnostic, frame::Frame, packet::Packet, registry::Registry,
};

use super::plan::packet::sent_probe_matches;
use super::profile;
use super::report::RttAccumulator;
use super::{Classification, Event, Probe, ProbeEvidence, Reply};
use crate::correlation::{Correlation, Transport};
use crate::evidence::SentPacket;
use crate::probe::ProbeStatus;
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
    let observation = crate::correlation::observe(registry, transport, request, response)?;
    let classification = match observation.correlation {
        Correlation::TcpReset | Correlation::PortUnreachable => Classification::Closed,
        Correlation::TcpSynAck | Correlation::UdpReply | Correlation::IcmpReply => {
            Classification::Open
        }
        Correlation::TcpOther => Classification::Unknown,
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

pub(super) struct Observation {
    pub(super) response: CorrelatedResponse,
    pub(super) application: Option<profile::Evidence>,
}

impl Observation {
    pub(super) fn observe(
        registry: &Registry,
        probe: &Probe,
        sent: &Packet,
        response: &DecodedPacket,
    ) -> Option<Self> {
        let classified = classify_response(registry, probe.endpoint.transport(), sent, response)?;
        Some(Self {
            response: classified,
            application: profile::evidence(probe, sent, response),
        })
    }

    /// The transport classification decides first; application evidence
    /// breaks ties inside one classification, and an unprofiled response
    /// ranks between failed and confirmed application evidence.
    pub(super) fn rank(&self) -> u8 {
        self.response.classification.rank() * 4
            + self.application.as_ref().map_or(2, profile::Evidence::rank)
    }
}

pub(super) struct ProbeClassifier<'a> {
    pub(super) registry: &'a Registry,
    pub(super) target: Arc<str>,
    pub(super) winners: HashMap<super::report::EndpointKey, Classification>,
    pub(super) rtt: RttAccumulator,
}

impl Classifier for ProbeClassifier<'_> {
    type Probe = Probe;
    type Observation = Observation;
    type Event = Event;

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

    fn evidence(
        &mut self,
        probe: &Probe,
        sent: &SentPacket,
        outcome: Outcome<Observation>,
    ) -> Event {
        let mut evidence = ProbeEvidence {
            sequence: probe.sequence,
            address: probe.address,
            scope: probe.scope.clone(),
            transport: probe.endpoint.transport(),
            port: probe.endpoint.port(),
            attempt: probe.attempt,
            status: ProbeStatus::Timeout,
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
        if let Outcome::Reply(reply) = outcome {
            self.rtt.note_received(reply.latency);
            evidence.status = ProbeStatus::Response;
            evidence.classification = reply.observation.response.classification;
            evidence.reply = Some(reply.observation.response.reply);
            evidence.responder = Some(reply.observation.response.responder);
            evidence.received_at = reply.received_at;
            evidence.latency = Some(reply.latency);
            evidence.response = reply.frame;
            evidence.reason = reply.observation.response.reason.to_owned();
            evidence.application = reply.observation.application;
        }
        self.winners
            .entry((
                evidence.address,
                evidence.transport,
                evidence.port,
                evidence.scope.as_ref().map(|scope| scope.interface.clone()),
            ))
            .or_insert(Classification::Timeout)
            .promote(evidence.classification);
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
