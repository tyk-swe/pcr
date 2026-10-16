// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::net::IpAddr;

use crate::packet::Packet;

/// Where several matchers attribute the same response, the highest `confidence` wins.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Match {
    pub confidence: u8,
}

impl Match {
    #[must_use]
    pub const fn new(confidence: u8) -> Self {
        Self { confidence }
    }
}

pub trait ResponseMatcher: Send + Sync + fmt::Debug {
    /// Whether every match has a common necessary key in
    /// [`crate::protocol::response_identity::request`] and
    /// [`crate::protocol::response_identity::response`]. Keys only narrow
    /// candidate discovery; callers must still invoke `matches`.
    ///
    /// The conservative default preserves arbitrary custom matcher semantics.
    /// Returning `true` opts into the built-in outer address/transport identity
    /// contract, including directly received quoted ICMP errors. Unknown shapes
    /// for which either helper returns `None` always require conservative lookup.
    fn uses_builtin_response_identity(&self) -> bool {
        false
    }

    fn matches(&self, request: &Packet, response: &Packet) -> Option<Match>;

    fn responder(&self, _request: &Packet, _response: &Packet) -> Option<IpAddr> {
        None
    }
}
