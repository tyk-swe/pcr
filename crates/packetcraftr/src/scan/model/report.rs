// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Serialize;

use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;

use crate::Stats;

use super::request::Transport;

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

pub use crate::probe::ProbeStatus;

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
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub endpoints: Vec<Endpoint>,
    pub undecoded: Vec<Frame>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}

#[derive(Clone, Debug)]
pub enum Event {
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
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub counts: ClassificationCounts,
    pub stats: Stats,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::assert_names_match_serialization;

    /// One vocabulary: what the CLI prints for a probe is what the JSON
    /// document calls it.
    #[test]
    fn names_match_the_serialized_names() {
        assert_names_match_serialization(
            [
                Classification::Open,
                Classification::Closed,
                Classification::Filtered,
                Classification::Unreachable,
                Classification::Unknown,
                Classification::Timeout,
            ],
            |value| value.as_str(),
        );
        assert_names_match_serialization([ProbeStatus::Response, ProbeStatus::Timeout], |value| {
            value.as_str()
        });
    }
}
