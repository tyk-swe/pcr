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
    fn matches(&self, request: &Packet, response: &Packet) -> Option<Match>;

    fn responder(&self, _request: &Packet, _response: &Packet) -> Option<IpAddr> {
        None
    }
}
