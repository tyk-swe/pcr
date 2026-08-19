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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Response,
    Timeout,
}

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
pub struct Result {
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

#[derive(Clone, Debug)]
pub struct Summary {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}
