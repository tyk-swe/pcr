// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! How traceroute reads, ranks, and reports one probe's evidence.

use std::net::IpAddr;
use std::sync::Arc;

use packetcraftr_core::{
    decode::DecodedPacket, diagnostic::Diagnostic, frame::Frame, packet::Packet, registry::Registry,
};

use super::classification::classify_response;
use super::plan::packet::sent_probe_matches;
use super::{
    Completion, Event, Probe, ProbeEvidence, ResponseClassification, ResponseKind,
    UndecodedEvidence,
};
use crate::SentPacket;
use crate::probe::ProbeStatus;
use crate::probe::runner::{Classifier, NO_RESPONSE_REASON, Outcome};

/// Traceroute's batch-evidence hook. It also tracks how the trace completes;
/// a destination or unreachable answer ends the trace after its hop.
pub(super) struct ProbeClassifier<'a> {
    pub(super) registry: &'a Registry,
    pub(super) target: Arc<str>,
    pub(super) completion: Completion,
}

impl ProbeClassifier<'_> {
    fn observe(&mut self, probe: &ProbeEvidence) {
        self.completion = match (self.completion, probe.response_kind, probe.status) {
            (_, Some(ResponseKind::DestinationReached), _)
            | (Completion::DestinationReached, _, _) => Completion::DestinationReached,
            (_, Some(ResponseKind::Unreachable), _) | (Completion::Unreachable, _, _) => {
                Completion::Unreachable
            }
            (_, _, ProbeStatus::Response) => Completion::MaximumHops,
            (completion, _, _) => completion,
        };
    }
}

impl Classifier for ProbeClassifier<'_> {
    type Probe = Probe;
    type Observation = ResponseClassification;
    type Event = Event;

    fn sent_matches(&self, probe: &Probe, sent: &Packet) -> bool {
        sent_probe_matches(probe, sent)
    }

    fn classify(
        &self,
        probe: &Probe,
        sent: &SentPacket,
        response: &DecodedPacket,
    ) -> Option<ResponseClassification> {
        classify_response(
            self.registry,
            probe.target.transport(),
            &sent.built().packet,
            response,
        )
    }

    fn rank(&self, observation: &ResponseClassification) -> u8 {
        observation.kind.rank()
    }

    fn responder(&self, observation: &ResponseClassification) -> IpAddr {
        observation.responder
    }

    fn evidence(
        &mut self,
        probe: &Probe,
        sent: &SentPacket,
        outcome: Outcome<ResponseClassification>,
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
