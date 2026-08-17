// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use serde::Serialize;

use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;

use crate::Stats;

use super::request::Strategy;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Response,
    Timeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseKind {
    Intermediate,
    DestinationReached,
    Unreachable,
}

impl ResponseKind {
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
pub struct Result {
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
