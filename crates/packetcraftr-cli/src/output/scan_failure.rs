// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Scan evidence a failed run still publishes on the shared error envelope.

use std::net::IpAddr;

use serde::Serialize;

use packetcraftr::probe;
use packetcraftr::probe::Transport;
use packetcraftr::scan as library;

use super::capture::Stats as CaptureStats;
use super::contract::Error;
use super::envelope::Stats;
use super::frame::{Captured, Timestamp, Wire};
use super::network::{InterfaceId, MaterializedRoute};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Scope {
    pub zone: String,
    pub interface: InterfaceId,
}

impl From<&packetcraftr::target::ResolvedZone> for Scope {
    fn from(scope: &packetcraftr::target::ResolvedZone) -> Self {
        Self {
            zone: scope.zone.as_str().to_owned(),
            interface: (&scope.interface).into(),
        }
    }
}

published_enum! {
    pub enum Stage from library::Stage {
        Discovery => "discovery",
        Scan => "scan",
    }
}

/// The published name of a correlated scan reply.
pub(crate) const fn reply_name(reply: library::Reply) -> &'static str {
    match reply {
        library::Reply::TcpSynAck => "tcp_syn_ack",
        library::Reply::TcpReset => "tcp_reset",
        library::Reply::TcpOther => "tcp_other",
        library::Reply::UdpPayload => "udp_payload",
        library::Reply::SctpInitAck => "sctp_init_ack",
        library::Reply::SctpAbort => "sctp_abort",
        library::Reply::SctpOther => "sctp_other",
        library::Reply::IcmpEchoReply => "icmp_echo_reply",
        library::Reply::IcmpTimestampReply => "icmp_timestamp_reply",
        library::Reply::IcmpNetmaskReply => "icmp_netmask_reply",
        library::Reply::IpProtocolPayload => "ip_protocol_payload",
        library::Reply::IcmpPortUnreachable => "icmp_port_unreachable",
        library::Reply::IcmpProtocolUnreachable => "icmp_protocol_unreachable",
        library::Reply::IcmpAdministrativelyProhibited => "icmp_administratively_prohibited",
        library::Reply::IcmpDestinationUnreachable => "icmp_destination_unreachable",
        library::Reply::IcmpTimeExceeded => "icmp_time_exceeded",
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

pub(crate) fn coverage(value: library::Coverage) -> &'static str {
    match value {
        library::Coverage::Pending => "pending",
        library::Coverage::Unknown => "unknown",
        library::Coverage::NoReportedLoss => "no_reported_loss",
        library::Coverage::Incomplete => "incomplete",
        library::Coverage::TransportTimeout => "transport_timeout",
    }
}

/// The effective TCP segment a raw scan sends to TCP scan endpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TcpScan {
    pub mode: TcpMode,
    pub flags: u16,
}

impl From<library::TcpScan> for TcpScan {
    fn from(mode: library::TcpScan) -> Self {
        Self {
            mode: mode.into(),
            flags: mode.flags(),
        }
    }
}

/// The effective SCTP chunk a raw scan sends to SCTP scan endpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SctpScan {
    pub mode: SctpMode,
    pub chunk_type: u8,
}

impl From<library::SctpScan> for SctpScan {
    fn from(mode: library::SctpScan) -> Self {
        Self {
            mode: mode.into(),
            chunk_type: mode.chunk_type(),
        }
    }
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
    pub frame: Wire,
    pub route: MaterializedRoute,
}

/// The ICMP request kind an endpoint variant publishes; echo stays implicit.
pub(crate) fn icmp_request(endpoint: probe::Endpoint) -> Option<&'static str> {
    match endpoint {
        probe::Endpoint::IcmpTimestamp => Some("timestamp"),
        probe::Endpoint::IcmpNetmask => Some("netmask"),
        _ => None,
    }
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
            icmp_request: icmp_request(probe.endpoint),
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Pending {
    pub sent: Sent,
    pub response: Option<Captured>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FailedProbe {
    pub sequence: u64,
    pub stage: Stage,
    pub destination: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    pub destination_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_protocol: Option<u8>,
    pub transport: crate::output::network::Transport,
    pub attempt: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CaptureSource {
    pub observation_quality: &'static str,
    pub interface: InterfaceId,
    pub ready: bool,
    pub shutdown_confirmed: bool,
    pub statistics_valid: bool,
    pub statistics: CaptureStats,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Failure {
    pub stats: Stats,
    pub pending: Vec<Pending>,
    pub failed_probe: Option<FailedProbe>,
    pub capture_sources: Vec<CaptureSource>,
}

impl TryFrom<&library::PipelineFailure> for Failure {
    type Error = Error;

    fn try_from(error: &library::PipelineFailure) -> Result<Self, Error> {
        Ok(Self {
            stats: error.stats.clone().into(),
            pending: error
                .pending
                .iter()
                .map(|entry| {
                    Ok(Pending {
                        sent: entry.sent.clone().try_into()?,
                        response: entry.response.clone().map(Captured::try_from).transpose()?,
                    })
                })
                .collect::<Result<_, Error>>()?,
            failed_probe: error.failed_probe.as_ref().map(|probe| FailedProbe {
                sequence: probe.sequence,
                stage: probe.stage.into(),
                destination: probe.address,
                scope: probe.scope.as_ref().map(Scope::from),
                destination_port: probe.endpoint.port(),
                ip_protocol: probe.endpoint.ip_protocol(),
                transport: probe.endpoint.transport().into(),
                attempt: probe.attempt,
            }),
            capture_sources: error
                .capture_sources
                .iter()
                .map(|source| CaptureSource {
                    observation_quality: coverage(source.observation_quality.into()),
                    interface: (&source.metadata.interface).into(),
                    ready: source.ready,
                    shutdown_confirmed: source.shutdown_confirmed,
                    statistics_valid: source.statistics_valid,
                    statistics: source.statistics.into(),
                })
                .collect(),
        })
    }
}

published_enum! {
    pub enum SctpMode from library::SctpScan {
        Init => "init",
        CookieEcho => "cookie_echo",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpMode {
    Syn,
    Ack,
    Window,
    Fin,
    Null,
    Xmas,
    Maimon,
    Custom,
}
impl From<library::TcpScan> for TcpMode {
    fn from(value: library::TcpScan) -> Self {
        match value {
            library::TcpScan::Syn => Self::Syn,
            library::TcpScan::Ack => Self::Ack,
            library::TcpScan::Window => Self::Window,
            library::TcpScan::Fin => Self::Fin,
            library::TcpScan::Null => Self::Null,
            library::TcpScan::Xmas => Self::Xmas,
            library::TcpScan::Maimon => Self::Maimon,
            library::TcpScan::Custom { .. } => Self::Custom,
        }
    }
}

impl TcpMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Syn => "syn",
            Self::Ack => "ack",
            Self::Window => "window",
            Self::Fin => "fin",
            Self::Null => "null",
            Self::Xmas => "xmas",
            Self::Maimon => "maimon",
            Self::Custom => "custom",
        }
    }
}
