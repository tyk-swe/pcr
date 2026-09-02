// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Probe vocabulary shared by the scan and traceroute workflows.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The wire protocol a probe is sent over, as a request names it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    /// The traceroute default.
    #[default]
    Udp,
    Icmp,
}

impl Transport {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
        }
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The transport-specific destination one probe addresses.
///
/// Pairing each transport with exactly the addressing it needs makes a
/// portless TCP or UDP probe — and a ported ICMP probe — unrepresentable, so
/// probe construction never has to unwrap a port that a different module
/// validated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeEndpoint {
    Tcp { port: u16 },
    Udp { port: u16 },
    Icmp,
}

impl ProbeEndpoint {
    #[must_use]
    pub const fn transport(self) -> Transport {
        match self {
            Self::Tcp { .. } => Transport::Tcp,
            Self::Udp { .. } => Transport::Udp,
            Self::Icmp => Transport::Icmp,
        }
    }

    /// The destination port, absent for the portless ICMP endpoint.
    #[must_use]
    pub const fn port(self) -> Option<u16> {
        match self {
            Self::Tcp { port } | Self::Udp { port } => Some(port),
            Self::Icmp => None,
        }
    }
}

/// Whether a probe was answered before its timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Response,
    Timeout,
}

impl ProbeStatus {
    /// The name the CLI prints, identical to the serialized one.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Response => "response",
            Self::Timeout => "timeout",
        }
    }
}
