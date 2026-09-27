// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! How traceroute classifies, ranks, and reports one probe's evidence.

use std::net::IpAddr;
use std::sync::Arc;

use packetcraftr_core::{
    decode::DecodedPacket, diagnostic::Diagnostic, frame::Frame, packet::Packet, registry::Registry,
};

use packetcraftr_core::protocol::BuiltinProtocol;
use packetcraftr_core::protocol::semantics;

use super::plan::packet::sent_probe_matches;
use super::{Event, Probe, ProbeEvidence, ResponseKind, Termination, UndecodedEvidence};
use crate::correlation::{self, Correlation, Transport};
use crate::evidence::SentPacket;
use crate::probe::ProbeStatus;
use crate::probe::runner::{Classifier, NO_RESPONSE_REASON, Outcome};

/// A checksum-valid response correlated to one probe: what kind of hop
/// answered, who answered, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorrelatedResponse {
    pub kind: ResponseKind,
    pub responder: IpAddr,
    pub reason: &'static str,
}

/// Pure traceroute classifier. Corrupt, unrelated, pre-probe, and
/// protocol-inconsistent traffic returns `None` and cannot advance the trace.
pub fn classify_response(
    registry: &Registry,
    strategy: Transport,
    request: &Packet,
    response: &DecodedPacket,
) -> Option<CorrelatedResponse> {
    let observation = correlation::observe(registry, strategy, request, response)?;
    let destination = packet_destination(request, strategy)?;
    let kind = match observation.correlation {
        Correlation::TimeExceeded => ResponseKind::Intermediate,
        correlation if correlation.is_direct_reply() => {
            if observation.responder != destination {
                return None;
            }
            ResponseKind::DestinationReached
        }
        Correlation::PortUnreachable
            if strategy == Transport::Udp && observation.responder == destination =>
        {
            ResponseKind::DestinationReached
        }
        _ => ResponseKind::Unreachable,
    };
    Some(CorrelatedResponse {
        kind,
        responder: observation.responder,
        reason: observation.reason,
    })
}

fn packet_destination(packet: &Packet, strategy: Transport) -> Option<IpAddr> {
    let transport = match strategy {
        Transport::Tcp => Some(BuiltinProtocol::Tcp),
        Transport::Udp => Some(BuiltinProtocol::Udp),
        Transport::Icmp => None,
    };
    let transport_index = packet.iter().position(|layer| match transport {
        Some(transport) => BuiltinProtocol::of(layer) == Some(transport),
        None => matches!(
            BuiltinProtocol::of(layer),
            Some(BuiltinProtocol::Icmpv4 | BuiltinProtocol::Icmpv6)
        ),
    })?;
    let path = semantics::enclosing_ip_path(packet, transport_index).ok()??;
    Some(path.final_destination)
}

/// Traceroute's batch-evidence hook. It also tracks how the trace completes;
/// a destination or unreachable answer ends the trace after its hop.
pub(super) struct ProbeClassifier<'a> {
    pub(super) registry: &'a Registry,
    pub(super) target: Arc<str>,
    pub(super) termination: Termination,
}

impl ProbeClassifier<'_> {
    fn observe(&mut self, probe: &ProbeEvidence) {
        self.termination = match (self.termination, probe.response_kind, probe.status) {
            (_, Some(ResponseKind::DestinationReached), _)
            | (Termination::DestinationReached, _, _) => Termination::DestinationReached,
            (_, Some(ResponseKind::Unreachable), _) | (Termination::Unreachable, _, _) => {
                Termination::Unreachable
            }
            (_, _, ProbeStatus::Response) => Termination::MaximumHops,
            (termination, _, _) => termination,
        };
    }
}

impl Classifier for ProbeClassifier<'_> {
    type Probe = Probe;
    type Observation = CorrelatedResponse;
    type Event = Event;

    fn sent_matches(&self, probe: &Probe, sent: &Packet) -> bool {
        sent_probe_matches(probe, sent)
    }

    fn classify(
        &self,
        probe: &Probe,
        sent: &SentPacket,
        response: &DecodedPacket,
    ) -> Option<CorrelatedResponse> {
        classify_response(
            self.registry,
            probe.target.transport(),
            &sent.built().packet,
            response,
        )
    }

    fn rank(&self, observation: &CorrelatedResponse) -> u8 {
        observation.kind.rank()
    }

    fn responder(&self, observation: &CorrelatedResponse) -> IpAddr {
        observation.responder
    }

    fn evidence(
        &mut self,
        probe: &Probe,
        sent: &SentPacket,
        outcome: Outcome<CorrelatedResponse>,
    ) -> Event {
        let mut evidence = ProbeEvidence {
            sequence: probe.sequence,
            hop_limit: probe.hop_limit,
            attempt: probe.attempt,
            destination: probe.address,
            strategy: probe.target.transport(),
            destination_port: probe.target.port(),
            status: ProbeStatus::Timeout,
            response_kind: None,
            responder: None,
            sent_at: sent.timing().freshness_marker().wall_clock(),
            received_at: None,
            latency: None,
            response: None,
            reason: NO_RESPONSE_REASON.to_owned(),
        };
        if let Outcome::Reply(reply) = outcome {
            evidence.status = ProbeStatus::Response;
            evidence.response_kind = Some(reply.observation.kind);
            evidence.responder = Some(reply.observation.responder);
            evidence.received_at = reply.received_at;
            evidence.latency = Some(reply.latency);
            evidence.response = reply.frame;
            evidence.reason = reply.observation.reason.to_owned();
        }
        self.observe(&evidence);
        Event::Probe {
            target: Arc::clone(&self.target),
            probe: evidence,
        }
    }

    fn undecoded(&self, probes: &[Probe], frame: Frame) -> Event {
        let hop_limit = probes
            .first()
            .expect("serial traceroute retains undecoded frames with their hop batch")
            .hop_limit;
        Event::Undecoded(UndecodedEvidence { hop_limit, frame })
    }

    fn diagnostic(&self, diagnostic: Diagnostic) -> Event {
        Event::Diagnostic(diagnostic)
    }

    fn ends_operation(&self, event: &Event) -> bool {
        matches!(
            event,
            Event::Probe { probe, .. } if matches!(
                probe.response_kind,
                Some(ResponseKind::DestinationReached | ResponseKind::Unreachable)
            )
        )
    }
}
