// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured traceroute output.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use packetcraftr_packet::diagnostic::Diagnostic;
use packetcraftr_workflow::traceroute::Result as TracerouteResult;

use super::contract::Error;
use super::envelope::Stats;
use super::frame::Captured;

pub use super::frame::{Captured as Frame, Timestamp};

/// Output-v1 traceroute-probe status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Response,
    Timeout,
}

impl From<packetcraftr_workflow::traceroute::ProbeStatus> for ProbeStatus {
    fn from(value: packetcraftr_workflow::traceroute::ProbeStatus) -> Self {
        match value {
            packetcraftr_workflow::traceroute::ProbeStatus::Response => Self::Response,
            packetcraftr_workflow::traceroute::ProbeStatus::Timeout => Self::Timeout,
        }
    }
}

/// Output-v1 traceroute response classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseKind {
    Intermediate,
    DestinationReached,
    Unreachable,
}

impl From<packetcraftr_workflow::traceroute::ResponseKind> for ResponseKind {
    fn from(value: packetcraftr_workflow::traceroute::ResponseKind) -> Self {
        match value {
            packetcraftr_workflow::traceroute::ResponseKind::Intermediate => Self::Intermediate,
            packetcraftr_workflow::traceroute::ResponseKind::DestinationReached => {
                Self::DestinationReached
            }
            packetcraftr_workflow::traceroute::ResponseKind::Unreachable => Self::Unreachable,
        }
    }
}

/// Output-v1 traceroute completion reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Completion {
    DestinationReached,
    Unreachable,
    MaximumHops,
    Timeout,
}

impl From<packetcraftr_workflow::traceroute::Completion> for Completion {
    fn from(value: packetcraftr_workflow::traceroute::Completion) -> Self {
        match value {
            packetcraftr_workflow::traceroute::Completion::DestinationReached => {
                Self::DestinationReached
            }
            packetcraftr_workflow::traceroute::Completion::Unreachable => Self::Unreachable,
            packetcraftr_workflow::traceroute::Completion::MaximumHops => Self::MaximumHops,
            packetcraftr_workflow::traceroute::Completion::Timeout => Self::Timeout,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Probe {
    pub sequence: u64,
    pub hop_limit: u8,
    pub attempt: u32,
    pub strategy: String,
    pub destination: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    pub status: ProbeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_kind: Option<ResponseKind>,
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
pub struct Hop {
    pub hop_limit: u8,
    pub probes: Vec<Probe>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Undecoded {
    pub hop_limit: u8,
    pub frame: Captured,
}

/// Aggregate or streamed result of `traceroute`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Result {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub destination: IpAddr,
    pub strategy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    pub hops: Vec<Hop>,
    pub undecoded: Vec<Undecoded>,
    pub completion: Completion,
}

impl Result {
    pub fn try_from_traceroute(
        result: TracerouteResult,
    ) -> std::result::Result<(Self, Vec<Diagnostic>, Stats), Error> {
        let TracerouteResult {
            target,
            resolved_addresses,
            destination,
            strategy,
            destination_port,
            hops,
            undecoded,
            completion,
            diagnostics,
            stats,
        } = result;
        let hop_outputs = hops
            .into_iter()
            .map(|hop| {
                let probe_outputs = hop
                    .probes
                    .into_iter()
                    .map(|probe| {
                        Ok(Probe {
                            sequence: probe.sequence,
                            hop_limit: probe.hop_limit,
                            attempt: probe.attempt,
                            strategy: probe.strategy.to_string(),
                            destination: probe.destination,
                            destination_port: probe.destination_port,
                            status: probe.status.into(),
                            response_kind: probe.response_kind.map(Into::into),
                            responder: probe.responder,
                            sent_at: probe.sent_at.try_into()?,
                            received_at: probe.received_at.map(Timestamp::try_from).transpose()?,
                            latency: probe.latency,
                            frame: probe.response.map(Captured::try_from_frame).transpose()?,
                            reason: probe.reason,
                        })
                    })
                    .collect::<std::result::Result<Vec<_>, Error>>()?;
                Ok(Hop {
                    hop_limit: hop.hop_limit,
                    probes: probe_outputs,
                })
            })
            .collect::<std::result::Result<Vec<_>, Error>>()?;
        let undecoded_outputs = undecoded
            .into_iter()
            .map(|evidence| {
                Ok(Undecoded {
                    hop_limit: evidence.hop_limit,
                    frame: Captured::try_from_frame(evidence.frame)?,
                })
            })
            .collect::<std::result::Result<Vec<_>, Error>>()?;
        let operation_stats = stats.into();
        Ok((
            Self {
                target,
                resolved_addresses,
                destination,
                strategy: strategy.to_string(),
                destination_port,
                hops: hop_outputs,
                undecoded: undecoded_outputs,
                completion: completion.into(),
            },
            diagnostics,
            operation_stats,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Hop {
        target: String,
        destination: IpAddr,
        hop: Hop,
    },
    Undecoded {
        hop_limit: u8,
        frame: Captured,
    },
    Complete {
        target: String,
        resolved_addresses: Vec<IpAddr>,
        destination: IpAddr,
        strategy: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        destination_port: Option<u16>,
        completion: Completion,
    },
}
