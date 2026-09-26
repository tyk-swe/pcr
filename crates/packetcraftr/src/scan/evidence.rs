// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! How scan classifies, ranks, and reports one probe's evidence.

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

/// A checksum-valid response correlated to one probe: how it classifies the
/// probed endpoint, who answered, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorrelatedResponse {
    pub classification: Classification,
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
        responder: observation.responder,
        reason: observation.reason,
    })
}

/// One correlated scan response: its transport classification and, for a
/// profiled UDP port, the application evidence it carries.
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

/// Scan's batch-evidence hook. It also tallies what the summary reports: the
/// winning classification per endpoint and the round-trip samples.
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
            classification: Classification::Timeout,
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
            evidence.responder = Some(reply.observation.response.responder);
            evidence.received_at = reply.received_at;
            evidence.latency = Some(reply.latency);
            evidence.response = reply.frame;
            evidence.reason = reply.observation.response.reason.to_owned();
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
