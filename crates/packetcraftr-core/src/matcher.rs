// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Response-correlation extension contracts.

use std::fmt;
use std::net::IpAddr;

use crate::Packet;

/// One matcher's positive attribution of a response to a request.
///
/// A match exists or it does not, so the absence of one is `None` rather than
/// a value that carries a confidence. Where several matchers attribute the
/// same response, the highest `confidence` wins.
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
    /// Attributes `response` to `request`, or `None` when it does not belong
    /// to it.
    fn matches(&self, request: &Packet, response: &Packet) -> Option<Match>;

    /// Returns the network-layer source selected for a matched response when
    /// the matcher can identify one. The default reports no responder.
    fn responder(&self, _request: &Packet, _response: &Packet) -> Option<IpAddr> {
        None
    }
}
