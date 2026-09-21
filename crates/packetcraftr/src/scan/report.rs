// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use crate::probe::index_or_push;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Serialize;

use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;

use crate::Stats;

use crate::probe::{ProbeStatus, Transport};

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
    /// The name the CLI prints, identical to the serialized one.
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

    /// Replaces `self` when `candidate` outranks it, so every per-endpoint
    /// winner is chosen by the same rule.
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

packetcraftr_core::display_via_as_str!(Classification);

#[derive(Clone, Debug)]
pub struct ProbeEvidence {
    pub sequence: u64,
    pub address: IpAddr,
    pub transport: Transport,
    pub port: Option<u16>,
    pub attempt: u32,
    pub status: ProbeStatus,
    pub classification: Classification,
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
    pub transport: Transport,
    pub port: Option<u16>,
    pub classification: Classification,
    pub probes: Vec<ProbeEvidence>,
}

#[derive(Clone, Debug)]
pub struct Report {
    pub planned_duration: Duration,
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub endpoints: Vec<Endpoint>,
    pub undecoded: Vec<Frame>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
    pub rtt: Rtt,
}

/// Operation-level accounting for one bounded repeated-probe run.
///
/// `sent` counts probes whose transmission the provider confirmed (for the
/// socket path, connect calls the kernel admitted). `received` counts probes
/// that produced a definitive verdict inside their round's timeout: a
/// checksum-valid, protocol-consistent correlated response for packet
/// probes, or a connected/refused/unreachable connect verdict for TCP
/// connect. `lost` is `sent - received`. `min`, `avg`, and `max` summarize
/// one round-trip sample per received probe — the selected response's
/// latency, or the connect verdict's elapsed time — and are `None` when no
/// probe was received.
///
/// Each probe contributes at most one sample: duplicate responses inside one
/// round add neither samples nor counts, and a response arriving after its
/// round's window is unattributed evidence rather than a late `received`.
/// When the capture backend reports dropped frames, `lost` may count probes
/// whose replies arrived but were never delivered; the
/// `capture.evidence_incomplete` diagnostic marks that caveat.
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

/// Accumulates per-probe verdicts into the published [`Rtt`] totals.
#[derive(Clone, Debug, Default)]
pub(crate) struct RttAccumulator {
    sent: u64,
    received: u64,
    total: Duration,
    min: Option<Duration>,
    max: Option<Duration>,
}

impl RttAccumulator {
    /// Counts one probe whose transmission the provider confirmed.
    pub(crate) fn note_sent(&mut self) {
        self.sent = self.sent.saturating_add(1);
    }

    /// Counts one received verdict and folds its round-trip sample in.
    pub(crate) fn note_received(&mut self, sample: Duration) {
        self.received = self.received.saturating_add(1);
        self.total = self.total.saturating_add(sample);
        self.min = Some(self.min.map_or(sample, |min| min.min(sample)));
        self.max = Some(self.max.map_or(sample, |max| max.max(sample)));
    }

    /// Freezes the accumulated counts and samples into the reported form.
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
    pub sent: Arc<crate::SentPacket>,
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
    Diagnostic(Diagnostic),
}

/// Final scan metadata after every probe event was published. Diagnostics are
/// not repeated here: each one already reached the caller as
/// [`Event::Diagnostic`] when it was raised.
#[derive(Clone, Debug)]
pub struct Summary {
    /// Conservative receive-window and pacing bound, validated before sending.
    pub planned_duration: Duration,
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub counts: ClassificationCounts,
    pub stats: Stats,
    pub rtt: Rtt,
}

/// How many probed endpoints settled on each final classification, mirroring
/// traceroute's [`crate::traceroute::Completion`] rollup for streaming
/// consumers that never see the per-endpoint outcomes.
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

#[derive(Default)]
pub(super) struct Collector {
    endpoints: Vec<Endpoint>,
    endpoint_indices: HashMap<(IpAddr, Option<u16>), usize>,
    undecoded: Vec<Frame>,
    diagnostics: Vec<Diagnostic>,
}

impl Collector {
    pub(super) fn observe(&mut self, event: Event) {
        match event {
            Event::Sent(_) => {}
            Event::Probe { target: _, probe } => self.observe_probe(probe),
            Event::Undecoded { frame } => self.undecoded.push(frame),
            Event::Diagnostic(diagnostic) => self.diagnostics.push(diagnostic),
        }
    }

    fn observe_probe(&mut self, evidence: ProbeEvidence) {
        let address = evidence.address;
        let transport = evidence.transport;
        let port = evidence.port;
        let endpoint = index_or_push(
            &mut self.endpoints,
            &mut self.endpoint_indices,
            (address, port),
            || Endpoint {
                address,
                transport,
                port,
                classification: Classification::Timeout,
                probes: Vec::new(),
            },
        );
        endpoint.classification.promote(evidence.classification);
        endpoint.probes.push(evidence);
    }

    pub(super) fn finish(mut self, summary: Summary) -> Report {
        for endpoint in &mut self.endpoints {
            endpoint.probes.sort_by_key(|probe| probe.sequence);
        }
        self.endpoints
            .sort_by_key(|endpoint| endpoint.probes.first().map(|probe| probe.sequence));
        Report {
            planned_duration: summary.planned_duration,
            target: summary.target,
            resolved_addresses: summary.resolved_addresses,
            endpoints: self.endpoints,
            undecoded: self.undecoded,
            diagnostics: self.diagnostics,
            stats: summary.stats,
            rtt: summary.rtt,
        }
    }
}
