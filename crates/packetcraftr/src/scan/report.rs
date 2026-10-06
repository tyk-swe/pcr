// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Serialize;

use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;

use crate::correlation::Correlation;
use crate::execution::Shared;
use crate::probe::{ProbeStatus, Transport, index_or_push};
use crate::{Sink, Stats};
use packetcraftr_core::error::BoundaryError;

use super::Error;

/// What a correlated reply was, beside the classification it earned. Port
/// inference reads this rather than the classification, because one
/// classification can cover replies that mean different things per method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Reply {
    TcpSynAck,
    TcpReset,
    /// A correlated TCP segment that is neither SYN/ACK nor a reset.
    TcpOther,
    UdpPayload,
    IcmpEchoReply,
    IcmpPortUnreachable,
    IcmpAdministrativelyProhibited,
    /// Destination unreachable other than port unreachable or prohibition.
    IcmpDestinationUnreachable,
    IcmpTimeExceeded,
}

impl Reply {
    pub(crate) const fn from_correlation(correlation: Correlation) -> Self {
        match correlation {
            Correlation::TcpSynAck => Self::TcpSynAck,
            Correlation::TcpReset => Self::TcpReset,
            Correlation::TcpOther => Self::TcpOther,
            Correlation::UdpReply => Self::UdpPayload,
            Correlation::IcmpReply => Self::IcmpEchoReply,
            Correlation::PortUnreachable => Self::IcmpPortUnreachable,
            Correlation::AdministrativelyProhibited => Self::IcmpAdministrativelyProhibited,
            Correlation::DestinationUnreachable => Self::IcmpDestinationUnreachable,
            Correlation::TimeExceeded => Self::IcmpTimeExceeded,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Open,
    Closed,
    Filtered,
    Unreachable,
    Unknown,
    Timeout,
}

impl Classification {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Filtered => "filtered",
            Self::Unreachable => "unreachable",
            Self::Unknown => "unknown",
            Self::Timeout => "timeout",
        }
    }

    pub(in crate::scan) fn promote(&mut self, candidate: Self) {
        if candidate.rank() > self.rank() {
            *self = candidate;
        }
    }

    pub(in crate::scan) fn rank(self) -> u8 {
        match self {
            Self::Open => 6,
            Self::Closed => 5,
            Self::Filtered => 4,
            Self::Unreachable => 3,
            Self::Unknown => 2,
            Self::Timeout => 1,
        }
    }
}

impl std::fmt::Display for Classification {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug)]
pub struct ProbeEvidence {
    pub sequence: u64,
    pub address: IpAddr,
    pub scope: Option<crate::target::ResolvedZone>,
    pub transport: Transport,
    pub port: Option<u16>,
    pub attempt: u32,
    pub status: ProbeStatus,
    pub classification: Classification,
    /// The correlated reply; `None` when the attempt was silent.
    pub reply: Option<Reply>,
    pub responder: Option<IpAddr>,
    pub sent_at: SystemTime,
    pub received_at: Option<SystemTime>,
    pub latency: Option<Duration>,
    pub response: Option<Frame>,
    pub reason: String,
    pub application: Option<super::profile::Evidence>,
}

#[derive(Clone, Debug)]
pub struct Endpoint {
    pub address: IpAddr,
    pub scope: Option<crate::target::ResolvedZone>,
    pub transport: Transport,
    pub port: Option<u16>,
    /// The highest-ranked attempt observation.
    pub classification: Classification,
    /// The bundled catalog's name for this transport and port: a hint about
    /// a conventional assignment, never service identification.
    pub port_hint: Option<&'static str>,
    /// Absent for portless ICMP echo, which observes a host, not a port.
    pub inference: Option<super::Inference>,
    pub probes: Vec<ProbeEvidence>,
}

#[derive(Clone, Debug)]
pub struct Aggregate {
    pub planned_duration: Duration,
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub endpoints: Vec<Endpoint>,
    pub undecoded: Vec<Frame>,
    /// Correlated frames no probe outcome carries: late, duplicate, and
    /// ambiguous replies.
    pub unattributed: Vec<Unattributed>,
    pub diagnostics: Vec<Diagnostic>,
    pub retained_evidence_bytes: usize,
    pub stats: Stats,
    pub rtt: Rtt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attribution {
    /// Correlates with a probe whose outcome was already published: its
    /// window had closed or a definitive reply had settled it.
    Late,
    /// An additional reply to a probe whose outcome kept a higher-ranked or
    /// earlier reply.
    Duplicate,
    /// Correlates with more than one probe, so no outcome claimed it.
    Ambiguous,
}

impl Attribution {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Late => "late",
            Self::Duplicate => "duplicate",
            Self::Ambiguous => "ambiguous",
        }
    }
}

/// A correlated frame retained beside the probe outcomes rather than
/// discarded to force a single answer.
#[derive(Clone, Debug)]
pub struct Unattributed {
    pub attribution: Attribution,
    /// The probe the frame correlates with; absent when ambiguous.
    pub sequence: Option<u64>,
    pub frame: Frame,
}

/// Each probe contributes at most one sample: duplicate responses inside one
/// round add neither samples nor counts, and a response arriving after its
/// round's window is unattributed evidence rather than a late `received`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Rtt {
    pub sent: u64,
    pub received: u64,
    pub lost: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<Duration>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RttAccumulator {
    sent: u64,
    received: u64,
    total: Duration,
    min: Option<Duration>,
    max: Option<Duration>,
}

impl RttAccumulator {
    pub(crate) fn note_sent(&mut self) {
        self.sent = self.sent.saturating_add(1);
    }

    pub(crate) fn note_received(&mut self, sample: Duration) {
        self.received = self.received.saturating_add(1);
        self.total = self.total.saturating_add(sample);
        self.min = Some(self.min.map_or(sample, |min| min.min(sample)));
        self.max = Some(self.max.map_or(sample, |max| max.max(sample)));
    }

    pub(crate) fn finish(&self) -> Rtt {
        // received is bounded by the operation probe budget, far below u32::MAX;
        // checked_div guards the narrowing anyway.
        let avg = u32::try_from(self.received)
            .ok()
            .and_then(|count| self.total.checked_div(count));
        Rtt {
            sent: self.sent,
            received: self.received,
            lost: self.sent.saturating_sub(self.received),
            min: self.min,
            avg,
            max: self.max,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SentProbe {
    pub probe: super::Probe,
    pub sent: Arc<crate::evidence::SentPacket>,
}

#[derive(Clone, Debug)]
pub struct PendingEvidence {
    pub sent: SentProbe,
    pub response: Option<Frame>,
}

#[derive(Clone, Debug)]
pub enum Event {
    Sent(SentProbe),
    Probe {
        target: Arc<str>,
        probe: ProbeEvidence,
    },
    Undecoded {
        frame: Frame,
    },
    Unattributed(Unattributed),
    Diagnostic(Diagnostic),
}

/// Diagnostics are not repeated here: each one already reached the
/// caller as [`Event::Diagnostic`] when it was raised.
#[derive(Clone, Debug)]
pub struct Report {
    pub planned_duration: Duration,
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub counts: ClassificationCounts,
    pub retained_evidence_bytes: usize,
    pub stats: Stats,
    pub rtt: Rtt,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ClassificationCounts {
    pub open: usize,
    pub closed: usize,
    pub filtered: usize,
    pub unreachable: usize,
    pub unknown: usize,
    pub timeout: usize,
}

impl ClassificationCounts {
    pub(in crate::scan) fn increment(&mut self, classification: Classification) {
        let counter = match classification {
            Classification::Open => &mut self.open,
            Classification::Closed => &mut self.closed,
            Classification::Filtered => &mut self.filtered,
            Classification::Unreachable => &mut self.unreachable,
            Classification::Unknown => &mut self.unknown,
            Classification::Timeout => &mut self.timeout,
        };
        *counter = counter.saturating_add(1);
    }
}

#[derive(Clone, Default)]
pub struct Collector(Shared<Collected>);

/// Endpoint identity: TCP and UDP on one address and port never merge.
pub(in crate::scan) type EndpointKey = (
    IpAddr,
    Transport,
    Option<u16>,
    Option<packetcraftr_netio::interface::Id>,
);

#[derive(Default)]
struct Collected {
    endpoints: Vec<Endpoint>,
    endpoint_indices: HashMap<EndpointKey, usize>,
    probes: u64,
    undecoded: Vec<Frame>,
    unattributed: Vec<Unattributed>,
    diagnostics: Vec<Diagnostic>,
}

impl Sink<Event> for Collector {
    type Ack = ();

    fn publish(&mut self, event: Event) -> Result<(), BoundaryError> {
        self.0.update(|collected| collected.observe(event));
        Ok(())
    }
}

impl Collected {
    fn observe(&mut self, event: Event) {
        match event {
            Event::Sent(_) => {}
            Event::Probe { target: _, probe } => self.observe_probe(probe),
            Event::Undecoded { frame } => self.undecoded.push(frame),
            Event::Unattributed(unattributed) => self.unattributed.push(unattributed),
            Event::Diagnostic(diagnostic) => self.diagnostics.push(diagnostic),
        }
    }

    fn observe_probe(&mut self, evidence: ProbeEvidence) {
        self.probes = self.probes.saturating_add(1);
        let address = evidence.address;
        let transport = evidence.transport;
        let port = evidence.port;
        let scope = evidence.scope.clone();
        let interface = scope.as_ref().map(|scope| scope.interface.clone());
        let endpoint = index_or_push(
            &mut self.endpoints,
            &mut self.endpoint_indices,
            (address, transport, port, interface),
            || Endpoint {
                address,
                scope,
                transport,
                port,
                classification: Classification::Timeout,
                port_hint: port.and_then(|port| super::catalog::hint(transport, port)),
                inference: None,
                probes: Vec::new(),
            },
        );
        endpoint.classification.promote(evidence.classification);
        endpoint.probes.push(evidence);
    }
}

impl Collector {
    pub fn finish(self, report: Report) -> Result<Aggregate, Error> {
        let Collected {
            mut endpoints,
            probes,
            undecoded,
            unattributed,
            diagnostics,
            ..
        } = self.0.take();
        if probes != report.rtt.sent {
            return Err(Error::IncoherentEvents {
                message: format!(
                    "{probes} probe outcome(s) collected for {} sent probe(s)",
                    report.rtt.sent
                ),
            });
        }
        for endpoint in &mut endpoints {
            endpoint.probes.sort_by_key(|probe| probe.sequence);
            endpoint.inference = super::inference::raw(
                endpoint.transport,
                endpoint
                    .probes
                    .iter()
                    .map(|probe| (probe.sequence, probe.reply)),
            );
        }
        endpoints.sort_by_key(|endpoint| endpoint.probes.first().map(|probe| probe.sequence));
        Ok(Aggregate {
            planned_duration: report.planned_duration,
            target: report.target,
            resolved_addresses: report.resolved_addresses,
            endpoints,
            undecoded,
            unattributed,
            diagnostics,
            retained_evidence_bytes: report.retained_evidence_bytes,
            stats: report.stats,
            rtt: report.rtt,
        })
    }
}
