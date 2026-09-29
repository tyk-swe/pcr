// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use packetcraftr_core::{
    decode::DecodedPacket, diagnostic::Diagnostic, frame::Frame, packet::Packet, registry::Registry,
};

use super::plan::packet::sent_probe_matches;
use super::profile;
use super::report::RttAccumulator;
use super::{Classification, Event, Probe, ProbeEvidence};
use crate::correlation::{Correlation, Transport};
use crate::evidence::SentPacket;
use crate::probe::ProbeStatus;
use crate::probe::runner::{Classifier, NO_RESPONSE_REASON, Outcome};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorrelatedResponse {
    pub classification: Classification,
    pub responder: IpAddr,
    pub reason: &'static str,
    pub advertised_mtu: Option<u32>,
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
    let mode = request
        .get::<packetcraftr_core::protocol::transport::Tcp>()
        .map(|tcp| tcp.flags);
    let classification = match observation.correlation {
        Correlation::TcpReset if mode == Some(super::TcpMode::Ack.flags()) => {
            Classification::Unfiltered
        }
        Correlation::TcpReset | Correlation::PortUnreachable => Classification::Closed,
        Correlation::TcpSynAck if mode == Some(super::TcpMode::Syn.flags()) => Classification::Open,
        Correlation::UdpReply | Correlation::IcmpReply => Classification::Open,
        Correlation::TcpSynAck | Correlation::TcpOther => Classification::Unknown,
        Correlation::TimeExceeded | Correlation::AdministrativelyProhibited => {
            Classification::Filtered
        }
        Correlation::DestinationUnreachable | Correlation::PacketTooBig => {
            Classification::Unreachable
        }
    };
    Some(CorrelatedResponse {
        classification,
        responder: observation.responder,
        reason: observation.reason,
        advertised_mtu: observation.advertised_mtu,
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
    pub(super) winners: HashMap<(IpAddr, Option<u16>), Classification>,
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
            transport: probe.endpoint.transport(),
            port: probe.endpoint.port(),
            attempt: probe.attempt,
            status: ProbeStatus::Timeout,
            classification: if probe.endpoint.transport() == Transport::Tcp
                && probe.tcp_mode != super::TcpMode::Syn
            {
                probe.tcp_mode.silence()
            } else {
                Classification::Timeout
            },
            responder: None,
            sent_at: sent.timing().freshness_marker().wall_clock(),
            received_at: None,
            latency: None,
            response: None,
            reason: NO_RESPONSE_REASON.to_owned(),
            advertised_mtu: None,
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
            evidence.responder = Some(reply.observation.response.responder);
            evidence.received_at = reply.received_at;
            evidence.latency = Some(reply.latency);
            evidence.response = reply.frame;
            evidence.reason = reply.observation.response.reason.to_owned();
            evidence.advertised_mtu = reply.observation.response.advertised_mtu;
            evidence.application = reply.observation.application;
        }
        self.winners
            .entry((evidence.address, evidence.port))
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

    fn diagnostic(&self, diagnostic: Diagnostic) -> Event {
        Event::Diagnostic(diagnostic)
    }
}
