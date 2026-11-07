// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Per-probe evidence records: what the scan observed for a single probe.

use crate::output::published_enum;
use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use packetcraftr::scan as library;

use super::Classification;
use crate::output::contract::Error;
use crate::output::frame::{Captured, Timestamp};
use crate::output::scan_failure::{
    Protocol, Scope, SctpScan, Stage, TcpScan, coverage, icmp_request,
};

published_enum! {
    pub enum ApplicationStatus from library::profile::Status {
        NotObserved => "not_observed",
        Unchecked => "unchecked",
        Confirmed => "confirmed",
        Rejected => "rejected",
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ApplicationEvidence {
    pub profile: String,
    pub status: ApplicationStatus,
    pub reason: String,
}

impl From<library::profile::Evidence> for ApplicationEvidence {
    fn from(value: library::profile::Evidence) -> Self {
        Self {
            profile: value.profile,
            status: value.status.into(),
            reason: value.reason,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Measurement {
    Response,
    NoReply { coverage: &'static str },
    Unavailable,
}

impl From<library::Measurement<library::Reply>> for Measurement {
    fn from(value: library::Measurement<library::Reply>) -> Self {
        match value {
            library::Measurement::Response(_) => Self::Response,
            library::Measurement::NoReply(value) => Self::NoReply {
                coverage: coverage(value),
            },
            library::Measurement::Unavailable => Self::Unavailable,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Qualification {
    pub stage: Stage,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub coverage: &'static str,
}

impl From<library::Qualification> for Qualification {
    fn from(value: library::Qualification) -> Self {
        Self {
            stage: value.stage().into(),
            first_sequence: value.first_sequence(),
            last_sequence: value.last_sequence(),
            coverage: coverage(value.coverage()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Probe {
    pub measurement: Measurement,
    pub sequence: u64,
    pub stage: Stage,
    pub protocol: Protocol,
    pub destination: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_protocol: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_request: Option<&'static str>,
    /// The TCP segment a raw TCP probe sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_scan: Option<TcpScan>,
    /// The SCTP chunk a raw SCTP probe sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sctp_scan: Option<SctpScan>,
    pub attempt: u32,
    pub status: crate::output::network::ProbeStatus,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application: Option<ApplicationEvidence>,
    /// The window the correlated TCP response advertised, as observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_window: Option<u16>,
}

impl TryFrom<library::ProbeEvidence> for Probe {
    type Error = Error;

    fn try_from(evidence: library::ProbeEvidence) -> Result<Self, Error> {
        Ok(Self {
            measurement: evidence.measurement.into(),
            sequence: evidence.sequence,
            stage: evidence.stage.into(),
            protocol: (evidence.endpoint.transport(), evidence.address).into(),
            destination: evidence.address,
            scope: evidence.scope.as_ref().map(Scope::from),
            destination_port: evidence.endpoint.port(),
            ip_protocol: evidence.endpoint.ip_protocol(),
            icmp_request: icmp_request(evidence.endpoint),
            tcp_scan: evidence.tcp_scan.map(TcpScan::from),
            sctp_scan: evidence.sctp_scan.map(SctpScan::from),
            attempt: evidence.attempt,
            status: evidence.status.into(),
            classification: evidence.classification.into(),
            responder: evidence.responder,
            sent_at: evidence.sent_at.try_into()?,
            received_at: evidence.received_at.map(Timestamp::try_from).transpose()?,
            latency: evidence.latency,
            frame: evidence.response.map(Captured::try_from).transpose()?,
            reason: evidence.reason,
            application: evidence.application.map(Into::into),
            tcp_window: evidence.tcp_window,
        })
    }
}

#[cfg(test)]
mod tests;
