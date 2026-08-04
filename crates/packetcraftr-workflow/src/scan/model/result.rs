// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use serde::Serialize;

use packetcraftr_capture::Frame;
use packetcraftr_packet::diagnostic::Diagnostic;

use crate::Stats;

use super::request::ScanTransport;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanClassification {
    Open,
    Closed,
    Filtered,
    Unreachable,
    Unknown,
    Timeout,
}

impl ScanClassification {
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
pub enum ScanProbeStatus {
    Response,
    Timeout,
}

#[derive(Clone, Debug)]
pub struct ScanProbeEvidence {
    pub attempt: u32,
    pub status: ScanProbeStatus,
    pub classification: ScanClassification,
    pub responder: Option<IpAddr>,
    pub sent_at: SystemTime,
    pub received_at: Option<SystemTime>,
    pub latency: Option<Duration>,
    pub response: Option<Frame>,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct ScanEndpointResult {
    pub address: IpAddr,
    pub transport: ScanTransport,
    pub port: Option<u16>,
    pub classification: ScanClassification,
    pub evidence: Vec<ScanProbeEvidence>,
}

#[derive(Clone, Debug)]
pub struct ScanResult {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub endpoints: Vec<ScanEndpointResult>,
    pub undecoded: Vec<Frame>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}
