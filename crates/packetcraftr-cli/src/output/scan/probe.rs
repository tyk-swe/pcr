// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Per-probe evidence records: what the scan observed for a single probe.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use packetcraftr::probe::{self, Transport};

use packetcraftr::scan as library;

use super::plan::{SctpScan, TcpScan};
use super::{Classification, Scope, Stage};
use crate::output::contract::Error;
use crate::output::frame::{Captured, Timestamp};

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
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
    Icmpv4,
    Icmpv6,
    Ip,
}

impl From<(Transport, IpAddr)> for Protocol {
    fn from((transport, address): (Transport, IpAddr)) -> Self {
        match (transport, address) {
            (Transport::Tcp, _) => Self::Tcp,
            (Transport::Udp, _) => Self::Udp,
            (Transport::Sctp, _) => Self::Sctp,
            (Transport::Icmp, IpAddr::V4(_)) => Self::Icmpv4,
            (Transport::Icmp, IpAddr::V6(_)) => Self::Icmpv6,
            (Transport::Ip, _) => Self::Ip,
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

pub(crate) fn coverage(value: library::Coverage) -> &'static str {
    match value {
        library::Coverage::Pending => "pending",
        library::Coverage::Unknown => "unknown",
        library::Coverage::NoReportedLoss => "no_reported_loss",
        library::Coverage::Incomplete => "incomplete",
        library::Coverage::TransportTimeout => "transport_timeout",
    }
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
    pub status: probe::Status,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Sent {
    pub sequence: u64,
    pub stage: Stage,
    pub protocol: Protocol,
    pub destination: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    pub destination_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_protocol: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_request: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_scan: Option<TcpScan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sctp_scan: Option<SctpScan>,
    pub attempt: u32,
    pub sent_at: Timestamp,
    pub udp_profile: Option<String>,
    pub frame: crate::output::frame::Wire,
    pub route: crate::output::send::MaterializedRoute,
}

impl TryFrom<library::SentProbe> for Sent {
    type Error = Error;

    fn try_from(value: library::SentProbe) -> Result<Self, Error> {
        let probe = value.probe;
        let sent = value.sent;
        Ok(Self {
            sequence: probe.sequence,
            stage: probe.stage.into(),
            udp_profile: probe
                .udp_profile
                .as_ref()
                .map(|profile| profile.name().to_owned()),
            protocol: (probe.endpoint.transport(), probe.address).into(),
            destination: probe.address,
            scope: probe.scope.as_ref().map(Scope::from),
            destination_port: probe.endpoint.port(),
            ip_protocol: probe.endpoint.ip_protocol(),
            icmp_request: probe
                .endpoint
                .icmp_request_kind()
                .filter(|kind| *kind != "echo"),
            tcp_scan: (probe.endpoint.transport() == Transport::Tcp)
                .then(|| TcpScan::from(probe.tcp_scan)),
            sctp_scan: (probe.endpoint.transport() == Transport::Sctp)
                .then(|| SctpScan::from(probe.sctp_scan)),
            attempt: probe.attempt,
            sent_at: Timestamp::try_from(sent.timing().freshness_marker().wall_clock())?,
            frame: sent.wire_bytes().clone().into(),
            route: sent.route().clone().try_into()?,
        })
    }
}

impl TryFrom<library::ProbeEvidence> for Probe {
    type Error = Error;

    fn try_from(evidence: library::ProbeEvidence) -> Result<Self, Error> {
        Ok(Self {
            measurement: evidence.measurement.into(),
            sequence: evidence.sequence,
            stage: evidence.stage.into(),
            protocol: (evidence.transport, evidence.address).into(),
            destination: evidence.address,
            scope: evidence.scope.as_ref().map(Scope::from),
            destination_port: evidence.port,
            ip_protocol: evidence.ip_protocol,
            icmp_request: evidence.icmp_request.filter(|kind| *kind != "echo"),
            tcp_scan: evidence.tcp_scan.map(TcpScan::from),
            sctp_scan: evidence.sctp_scan.map(SctpScan::from),
            attempt: evidence.attempt,
            status: evidence.status,
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
