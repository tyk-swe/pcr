// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured scan output.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use crate::scan::Result as ScanResult;
use packetcraftr_core::diagnostic::Diagnostic;

use super::contract::Error;
use super::envelope::Stats;
use super::frame::Captured;

pub use super::frame::{Captured as Frame, Timestamp};

/// Output-v1 scan classification.
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

impl From<crate::scan::Classification> for Classification {
    fn from(value: crate::scan::Classification) -> Self {
        match value {
            crate::scan::Classification::Open => Self::Open,
            crate::scan::Classification::Closed => Self::Closed,
            crate::scan::Classification::Filtered => Self::Filtered,
            crate::scan::Classification::Unreachable => Self::Unreachable,
            crate::scan::Classification::Unknown => Self::Unknown,
            crate::scan::Classification::Timeout => Self::Timeout,
        }
    }
}

/// Output-v1 scan-probe status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Response,
    Timeout,
}

impl From<crate::scan::ProbeStatus> for ProbeStatus {
    fn from(value: crate::scan::ProbeStatus) -> Self {
        match value {
            crate::scan::ProbeStatus::Response => Self::Response,
            crate::scan::ProbeStatus::Timeout => Self::Timeout,
        }
    }
}

/// Evidence common to scan and other active-probe tools.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Evidence {
    pub protocol: String,
    pub destination: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    pub attempt: u32,
    pub status: ProbeStatus,
    pub classification: Classification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responder: Option<IpAddr>,
    pub sent_at: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_at: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<Captured>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    pub address: IpAddr,
    pub transport: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub classification: Classification,
    pub evidence: Vec<Evidence>,
}

/// Aggregate or streamed result of `scan`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Result {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub endpoints: Vec<Endpoint>,
    pub undecoded: Vec<Captured>,
}

impl Result {
    pub fn try_from_scan(
        result: ScanResult,
    ) -> std::result::Result<(Self, Vec<Diagnostic>, Stats), Error> {
        let ScanResult {
            target,
            resolved_addresses,
            endpoints,
            undecoded,
            diagnostics,
            stats,
        } = result;
        let endpoint_outputs = endpoints
            .into_iter()
            .map(|endpoint| {
                let evidence_outputs = endpoint
                    .evidence
                    .into_iter()
                    .map(|evidence| {
                        let protocol = match (endpoint.transport, endpoint.address) {
                            (crate::scan::Transport::Icmp, IpAddr::V4(_)) => "icmpv4",
                            (crate::scan::Transport::Icmp, IpAddr::V6(_)) => "icmpv6",
                            _ => endpoint.transport.as_str(),
                        };
                        Ok(Evidence {
                            protocol: protocol.to_owned(),
                            destination: endpoint.address,
                            destination_port: endpoint.port,
                            attempt: evidence.attempt,
                            status: evidence.status.into(),
                            classification: evidence.classification.into(),
                            responder: evidence.responder,
                            sent_at: evidence.sent_at.try_into()?,
                            received_at: evidence
                                .received_at
                                .map(Timestamp::try_from)
                                .transpose()?,
                            latency: evidence.latency,
                            frame: evidence
                                .response
                                .map(Captured::try_from_frame)
                                .transpose()?,
                            reason: evidence.reason,
                        })
                    })
                    .collect::<std::result::Result<Vec<_>, Error>>()?;
                Ok(Endpoint {
                    address: endpoint.address,
                    transport: endpoint.transport.to_string(),
                    port: endpoint.port,
                    classification: endpoint.classification.into(),
                    evidence: evidence_outputs,
                })
            })
            .collect::<std::result::Result<Vec<_>, Error>>()?;
        Ok((
            Self {
                target,
                resolved_addresses,
                endpoints: endpoint_outputs,
                undecoded: Captured::try_from_frames(undecoded)?,
            },
            diagnostics,
            stats.into(),
        ))
    }
}

/// One independently useful event in structured scan streaming output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Endpoint {
        target: String,
        endpoint: Endpoint,
    },
    Undecoded {
        frame: Captured,
    },
    Complete {
        target: String,
        resolved_addresses: Vec<IpAddr>,
    },
}
