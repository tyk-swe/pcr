// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::sync::Arc;

use packetcraftr_core::document::os_fingerprints;
use packetcraftr_core::{
    decode::{DecodedPacket, Dissector},
    diagnostic::Diagnostic,
    frame::Frame,
    packet::Packet,
    protocol::network::{Icmpv4, Icmpv6},
    registry::Registry,
};

use super::{Event, Observation, ProbeEvidence, plan::PlannedProbe};
use crate::{
    correlation,
    evidence::SentPacket,
    execution::evidence::Passed,
    probe::runner::{Classifier, Outcome, UnsolicitedCapture},
};

pub(super) struct Response {
    pub responder: IpAddr,
    pub observation: Option<Observation>,
    pub reason: &'static str,
}

fn observation(probe: &PlannedProbe, packet: &Packet) -> Option<Observation> {
    let mut observed = os_fingerprints::extract(probe.kind?, packet)?;
    if probe.kind == Some(super::Probe::TimestampSyn)
        && let Some(echo) = observed.timestamp_echo
    {
        observed.suitable &= echo == probe.identity;
    }
    if probe.kind == Some(super::Probe::Echo) {
        let expected = probe.packet();
        observed.suitable &= if let Some(icmp) = expected.get::<Icmpv4>() {
            packet
                .get::<Icmpv4>()
                .is_some_and(|reply| reply.body == icmp.body)
        } else {
            let icmp = expected.get::<Icmpv6>().expect("IPv6 authored echo");
            packet
                .get::<Icmpv6>()
                .is_some_and(|reply| reply.body == icmp.body)
        };
    }
    Some(observed)
}

pub(super) fn classify(
    registry: &Registry,
    probe: &PlannedProbe,
    sent: &Packet,
    response: &DecodedPacket,
) -> Option<Response> {
    let kind = probe.kind?;
    let transport = if kind == super::Probe::Echo {
        crate::probe::Transport::Icmp
    } else {
        crate::probe::Transport::Tcp
    };
    let correlated = correlation::observe(registry, transport, sent, response)?;
    let observation =
        if correlated.responder == probe.address && correlated.correlation.is_direct_reply() {
            observation(probe, &response.packet)
        } else {
            None
        };
    Some(Response {
        responder: correlated.responder,
        observation,
        reason: correlated.reason,
    })
}

pub(super) struct Fingerprints<'a> {
    pub registry: &'a Arc<Registry>,
}

impl Classifier for Fingerprints<'_> {
    type Probe = PlannedProbe;
    type Observation = Response;
    type Event = Event;

    fn sent_matches(&self, probe: &PlannedProbe, sent: &Packet) -> bool {
        probe.sent_matches(sent)
    }
    fn classify(
        &self,
        probe: &PlannedProbe,
        sent: &SentPacket,
        response: &DecodedPacket,
    ) -> Option<Response> {
        classify(self.registry, probe, &sent.built().packet, response)
    }
    fn rank(&self, response: &Response) -> u8 {
        u8::from(response.observation.is_some())
    }
    fn responder(&self, response: &Response) -> IpAddr {
        response.responder
    }
    fn evidence(
        &mut self,
        probe: &PlannedProbe,
        sent: &SentPacket,
        outcome: Outcome<Response>,
    ) -> Event {
        let mut record = ProbeEvidence {
            sequence: probe.sequence,
            probe: probe.kind,
            attempt: probe.attempt,
            sent: sent.frame().clone(),
            response: None,
            observation: None,
            received_at: None,
            latency: None,
            reason: if probe.kind.is_none() {
                "RST cleanup transmitted"
            } else {
                "no eligible response"
            }
            .into(),
        };
        if let Outcome::Reply(reply) = outcome {
            record.response = reply.frame;
            // Fields cannot qualify a match after their supporting frame was refused.
            record.observation = record.response.as_ref().and(reply.observation.observation);
            record.received_at = reply.received_at;
            record.latency = Some(reply.latency);
            record.reason = reply.observation.reason.into();
        }
        Event::Probe(record)
    }
    fn passed(&self, probe: &PlannedProbe, passed: Passed, frame: Frame) -> Option<Event> {
        probe.kind?;
        let decoded = Dissector::new(Arc::clone(self.registry))
            .decode(frame.clone(), Default::default())
            .ok()?;
        let source = decoded
            .packet
            .get::<packetcraftr_core::protocol::network::Ipv4>()
            .map(|ip| IpAddr::V4(ip.source))
            .or_else(|| {
                decoded
                    .packet
                    .get::<packetcraftr_core::protocol::network::Ipv6>()
                    .map(|ip| IpAddr::V6(ip.source))
            });
        let observation = if source == Some(probe.address) && matches!(passed, Passed::Superseded) {
            observation(probe, &decoded.packet)
        } else {
            None
        };
        Some(Event::Additional {
            sequence: probe.sequence,
            observation,
            frame,
            reason: if matches!(passed, Passed::Late) {
                "late response"
            } else {
                "additional correlated response"
            }
            .into(),
        })
    }
    fn unsolicited(
        &self,
        probe: &PlannedProbe,
        _: &SentPacket,
        capture: &UnsolicitedCapture,
        _: bool,
    ) -> Option<Event> {
        Some(Event::Additional {
            sequence: probe.sequence,
            observation: None,
            frame: capture.decoded.frame.clone(),
            reason: if capture.correlation_expired {
                "late or unrelated response"
            } else {
                "unrelated capture"
            }
            .into(),
        })
    }
    fn undecoded(&self, _: &[PlannedProbe], frame: Frame) -> Event {
        Event::Undecoded(frame)
    }
    fn diagnostic(&self, diagnostic: Diagnostic) -> Event {
        Event::Diagnostic(diagnostic)
    }
}
