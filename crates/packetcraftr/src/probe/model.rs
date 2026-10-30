// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    #[default]
    Udp,
    Sctp,
    Icmp,
    Ip,
}

impl Transport {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Sctp => "sctp",
            Self::Icmp => "icmp",
            Self::Ip => "ip",
        }
    }
}

impl std::fmt::Display for Transport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Endpoint {
    Tcp {
        port: u16,
    },
    /// Discovery-only bare TCP ACK probe.
    TcpAck {
        port: u16,
    },
    Udp {
        port: u16,
    },
    Sctp {
        port: u16,
    },
    Icmp,
    /// Discovery-only IPv4 ICMP timestamp request (type 13, reply 14).
    IcmpTimestamp,
    /// Discovery-only IPv4 ICMP address mask request (type 17, reply 18).
    IcmpNetmask,
    Ip {
        protocol: u8,
    },
}

impl Endpoint {
    #[must_use]
    pub const fn transport(self) -> Transport {
        match self {
            Self::Tcp { .. } | Self::TcpAck { .. } => Transport::Tcp,
            Self::Udp { .. } => Transport::Udp,
            Self::Sctp { .. } => Transport::Sctp,
            Self::Icmp | Self::IcmpTimestamp | Self::IcmpNetmask => Transport::Icmp,
            Self::Ip { .. } => Transport::Ip,
        }
    }

    #[must_use]
    pub const fn port(self) -> Option<u16> {
        match self {
            Self::Tcp { port }
            | Self::TcpAck { port }
            | Self::Udp { port }
            | Self::Sctp { port } => Some(port),
            Self::Icmp | Self::IcmpTimestamp | Self::IcmpNetmask | Self::Ip { .. } => None,
        }
    }

    #[must_use]
    pub const fn ip_protocol(self) -> Option<u8> {
        match self {
            Self::Ip { protocol } => Some(protocol),
            _ => None,
        }
    }
}

/// Renders `tcp/80`, `tcp-ack/80`, `udp/53`, `sctp/80`, `ip/47`, or `icmp*`.
impl std::fmt::Display for Endpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp { port } => write!(formatter, "tcp/{port}"),
            Self::TcpAck { port } => write!(formatter, "tcp-ack/{port}"),
            Self::Udp { port } => write!(formatter, "udp/{port}"),
            Self::Sctp { port } => write!(formatter, "sctp/{port}"),
            Self::Icmp => formatter.write_str("icmp"),
            Self::IcmpTimestamp => formatter.write_str("icmp-timestamp"),
            Self::IcmpNetmask => formatter.write_str("icmp-netmask"),
            Self::Ip { protocol } => write!(formatter, "ip/{protocol}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Response,
    Timeout,
}

impl Status {
    /// The name the CLI prints, identical to the serialized one.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Response => "response",
            Self::Timeout => "timeout",
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The workflow stage a probe belongs to. Discovery probes come first and
/// share one sequence space with the scan probes after them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Stage {
    Discovery,
    Scan,
}
