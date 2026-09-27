// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;
use std::net::{IpAddr, SocketAddr};

/// TCP and UDP conversation indices are allocated independently.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamTransport {
    Tcp,
    Udp,
}

impl StreamTransport {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

display_via_as_str!(StreamTransport);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct StreamRef {
    pub transport: StreamTransport,
    pub index: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        SocketAddr::new(self.address, self.port).fmt(f)
    }
}
