// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::net::IpAddr;

use super::super::Packet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchResult {
    pub matched: bool,
    pub confidence: u8,
    pub reason: Option<String>,
}

impl MatchResult {
    pub fn no_match() -> Self {
        Self {
            matched: false,
            confidence: 0,
            reason: None,
        }
    }

    pub fn matched(confidence: u8, reason: impl Into<String>) -> Self {
        Self {
            matched: true,
            confidence,
            reason: Some(reason.into()),
        }
    }
}

/// Trusted in-process Rust response matcher.
pub trait NativeResponseMatcher: Send + Sync + fmt::Debug {
    fn matches(&self, request: &Packet, response: &Packet) -> MatchResult;

    fn responder(&self, _request: &Packet, _response: &Packet) -> Option<IpAddr> {
        None
    }
}
