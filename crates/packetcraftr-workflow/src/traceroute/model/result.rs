// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use serde::Serialize;

use packetcraftr_capture::Frame;
use packetcraftr_packet::diagnostic::Diagnostic;

use crate::Stats;

use super::request::TracerouteStrategy;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TracerouteProbeStatus {
    Response,
    Timeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TracerouteResponseKind {
    Intermediate,
    DestinationReached,
    Unreachable,
}

impl TracerouteResponseKind {
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
pub enum TracerouteCompletion {
    DestinationReached,
    Unreachable,
    MaximumHops,
    Timeout,
}

#[derive(Clone, Debug)]
pub struct TracerouteProbeEvidence {
    pub sequence: u64,
    pub hop_limit: u8,
    pub attempt: u32,
    pub destination: IpAddr,
    pub strategy: TracerouteStrategy,
    pub destination_port: Option<u16>,
    pub status: TracerouteProbeStatus,
    pub response_kind: Option<TracerouteResponseKind>,
    pub responder: Option<IpAddr>,
    pub sent_at: SystemTime,
    pub received_at: Option<SystemTime>,
    pub latency: Option<Duration>,
    pub response: Option<Frame>,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct TracerouteHopResult {
    pub hop_limit: u8,
    pub probes: Vec<TracerouteProbeEvidence>,
}

#[derive(Clone, Debug)]
pub struct TracerouteUndecodedEvidence {
    pub hop_limit: u8,
    pub frame: Frame,
}

#[derive(Clone, Debug)]
pub struct TracerouteResult {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub destination: IpAddr,
    pub strategy: TracerouteStrategy,
    pub destination_port: Option<u16>,
    pub hops: Vec<TracerouteHopResult>,
    pub undecoded: Vec<TracerouteUndecodedEvidence>,
    pub completion: TracerouteCompletion,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}
