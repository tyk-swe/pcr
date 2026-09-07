// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Conversation names and transport endpoints.

use serde::Serialize;
use std::net::{IpAddr, SocketAddr};

/// The transport namespace a conversation index belongs to.
///
/// TCP and UDP indices are allocated independently, so a bare number cannot
/// name a conversation in a capture that holds both.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamTransport {
    Tcp,
    Udp,
}

impl StreamTransport {
    /// The `tcp.stream`/`udp.stream` filter spelling, which is also the
    /// spelling every serialized form of this value uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

display_via_as_str!(StreamTransport);

/// One conversation: its transport namespace plus per-transport index,
/// matching the `tcp.stream` and `udp.stream` filter vocabularies.
///
/// This is both how a finding names the conversation it concerns and how a
/// caller selects the conversation to follow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct StreamRef {
    pub transport: StreamTransport,
    pub index: u64,
}

/// One endpoint of an IP transport conversation.
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
