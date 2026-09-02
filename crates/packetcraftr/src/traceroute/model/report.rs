// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Serialize;

use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;

use crate::Stats;

use super::request::Strategy;

pub use crate::probe::ProbeStatus;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseKind {
    Intermediate,
    DestinationReached,
    Unreachable,
}

impl ResponseKind {
    /// The name the CLI prints, identical to the serialized one.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Intermediate => "intermediate",
            Self::DestinationReached => "destination_reached",
            Self::Unreachable => "unreachable",
        }
    }

    pub(in crate::traceroute) const fn rank(self) -> u8 {
        match self {
            Self::Intermediate => 1,
            Self::Unreachable => 2,
            Self::DestinationReached => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Completion {
    DestinationReached,
    Unreachable,
    MaximumHops,
    Timeout,
}

impl Completion {
    /// The name the CLI prints, identical to the serialized one.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DestinationReached => "destination_reached",
            Self::Unreachable => "unreachable",
            Self::MaximumHops => "maximum_hops",
            Self::Timeout => "timeout",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProbeEvidence {
    pub sequence: u64,
    pub hop_limit: u8,
    pub attempt: u32,
    pub destination: IpAddr,
    pub strategy: Strategy,
    pub destination_port: Option<u16>,
    pub status: ProbeStatus,
    pub response_kind: Option<ResponseKind>,
    pub responder: Option<IpAddr>,
    pub sent_at: SystemTime,
    pub received_at: Option<SystemTime>,
    pub latency: Option<Duration>,
    pub response: Option<Frame>,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct Hop {
    pub hop_limit: u8,
    pub probes: Vec<ProbeEvidence>,
}

#[derive(Clone, Debug)]
pub struct UndecodedEvidence {
    pub hop_limit: u8,
    pub frame: Frame,
}

#[derive(Clone, Debug)]
pub struct Report {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub destination: IpAddr,
    pub strategy: Strategy,
    pub destination_port: Option<u16>,
    pub hops: Vec<Hop>,
    pub undecoded: Vec<UndecodedEvidence>,
    pub completion: Completion,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}

#[derive(Clone, Debug)]
pub enum Event {
    Probe {
        target: Arc<str>,
        probe: ProbeEvidence,
    },
    Undecoded(UndecodedEvidence),
    Diagnostic(Diagnostic),
}

/// Final trace metadata after every probe event was published. Diagnostics are
/// not repeated here: each one already reached the caller as
/// [`Event::Diagnostic`] when it was raised.
#[derive(Clone, Debug)]
pub struct Summary {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub destination: IpAddr,
    pub strategy: Strategy,
    pub destination_port: Option<u16>,
    pub completion: Completion,
    pub stats: Stats,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One vocabulary: what the CLI prints for a hop is what the JSON document
    /// calls it.
    #[test]
    fn names_match_the_serialized_names() {
        for status in [ProbeStatus::Response, ProbeStatus::Timeout] {
            let serialized = serde_json::to_value(status).expect("probe status is a name");
            assert_eq!(serialized.as_str(), Some(status.as_str()));
        }
        for kind in [
            ResponseKind::Intermediate,
            ResponseKind::DestinationReached,
            ResponseKind::Unreachable,
        ] {
            let serialized = serde_json::to_value(kind).expect("response kind is a name");
            assert_eq!(serialized.as_str(), Some(kind.as_str()));
        }
        for completion in [
            Completion::DestinationReached,
            Completion::Unreachable,
            Completion::MaximumHops,
            Completion::Timeout,
        ] {
            let serialized = serde_json::to_value(completion).expect("completion is a name");
            assert_eq!(serialized.as_str(), Some(completion.as_str()));
        }
    }
}
