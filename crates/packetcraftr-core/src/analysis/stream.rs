// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! How the analysis surface names one conversation.

use std::fmt;

/// The transport namespace a conversation index belongs to.
///
/// TCP and UDP indices are allocated independently, so a bare number cannot
/// name a conversation in a capture that holds both.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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

impl fmt::Display for StreamTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One conversation: its transport namespace plus per-transport index,
/// matching the `tcp.stream` and `udp.stream` filter vocabularies.
///
/// This is both how a finding names the conversation it concerns and how a
/// caller selects the conversation to follow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct StreamRef {
    pub transport: StreamTransport,
    pub index: u64,
}
