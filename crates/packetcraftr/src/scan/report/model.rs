// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Serialize;

use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;

use crate::Stats;
use crate::probe::{self, Reply, Transport};
use crate::scan::{
    self, Inference, Measurement, Probe, Qualification, Scheduling, SctpScan, Stage, TcpScan,
};

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
    /// Authoritative measurement; pending silence requires a qualification event.
    pub measurement: Measurement<Reply>,
    pub sequence: u64,
    pub stage: Stage,
    pub address: IpAddr,
    pub scope: Option<crate::target::ResolvedZone>,
    pub transport: Transport,
    pub port: Option<u16>,
    /// Selected IP protocol number (`0..=255`) for IP-protocol probes; `None`
    /// for other transports.
    pub ip_protocol: Option<u8>,
    /// ICMP request kind (`"echo"`, `"timestamp"`, or `"netmask"`) for ICMP
    /// probes; `None` for other transports.
    pub icmp_request: Option<&'static str>,
    /// The TCP segment mode a raw TCP probe carried; `None` for other
    /// transports.
    pub tcp_scan: Option<TcpScan>,
    /// The SCTP chunk mode a raw SCTP probe carried; `None` for other
    /// transports.
    pub sctp_scan: Option<SctpScan>,
    pub attempt: u32,
    pub status: probe::Status,
    pub classification: Classification,
    /// The correlated reply; consult `measurement` before interpreting `None`.
    pub reply: Option<Reply>,
    pub responder: Option<IpAddr>,
    pub sent_at: SystemTime,
    pub received_at: Option<SystemTime>,
    pub latency: Option<Duration>,
    pub response: Option<Frame>,
    pub reason: String,
    pub application: Option<scan::profile::Evidence>,
    /// The advertised window of the correlated TCP response, retained as
    /// observed; `None` for ICMP errors and silence.
    pub tcp_window: Option<u16>,
}

#[derive(Clone, Debug)]
pub struct Endpoint {
    pub address: IpAddr,
    pub scope: Option<crate::target::ResolvedZone>,
    pub transport: Transport,
    pub port: Option<u16>,
    pub ip_protocol: Option<u8>,
    /// The highest-ranked attempt observation.
    pub classification: Classification,
    /// The bundled catalog's name for this transport and port: a hint about
    /// a conventional assignment, never service identification.
    pub port_hint: Option<&'static str>,
    /// Absent for portless ICMP echo, which observes a host, not a port.
    pub inference: Option<Inference>,
    pub probes: Vec<ProbeEvidence>,
}

#[derive(Clone, Debug)]
pub struct Aggregate {
    pub planned_duration: Duration,
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    /// One record per selected target, in selection order.
    pub hosts: Vec<scan::discovery::Host>,
    /// Discovery probe outcomes in sequence order, exactly those the hosts
    /// list; [`Self::endpoints`] holds only the scan stage's.
    pub discovery: Vec<ProbeEvidence>,
    pub endpoints: Vec<Endpoint>,
    pub undecoded: Vec<Frame>,
    /// Correlated frames no probe outcome carries: late, duplicate, and
    /// ambiguous replies.
    pub unattributed: Vec<Unattributed>,
    pub diagnostics: Vec<Diagnostic>,
    pub retained_evidence_bytes: usize,
    pub stats: Stats,
    pub rtt: Rtt,
    pub scheduling: Scheduling,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attribution {
    /// Correlates with a probe whose outcome was already published: its
    /// window had closed or a definitive reply had settled it.
    Late,
    /// An additional in-window reply whose probe kept another reply, through
    /// candidate ordering or the response limit.
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
    /// Attempts whose local acquisition quality cannot support silence.
    pub unavailable: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<Duration>,
}

#[derive(Clone, Debug)]
pub struct SentProbe {
    pub probe: Probe,
    pub sent: Arc<crate::evidence::SentPacket>,
}

#[derive(Clone, Debug)]
pub struct PendingEvidence {
    pub sent: SentProbe,
    pub response: Option<Frame>,
}

// `allow`, not `expect`: variant sizes differ by target, and on Windows the
// lint does not fire.
#[allow(
    clippy::large_enum_variant,
    reason = "Probe, the largest variant, is published once per probe; boxing it would allocate per probe"
)]
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
    Qualification(Qualification),
}

/// Diagnostics are not repeated here: each one already reached the
/// caller as [`Event::Diagnostic`] when it was raised.
#[derive(Clone, Debug)]
pub struct Report {
    pub planned_duration: Duration,
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    /// One record per selected target, in selection order.
    pub hosts: Vec<scan::discovery::Host>,
    /// Counts the scan stage's endpoints only.
    pub counts: ClassificationCounts,
    pub retained_evidence_bytes: usize,
    pub stats: Stats,
    pub rtt: Rtt,
    pub scheduling: Scheduling,
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
