//! Response-correlation extension contracts.

use std::fmt;
use std::net::IpAddr;

use super::Packet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Result {
    pub matched: bool,
    pub confidence: u8,
    pub reason: Option<String>,
}

impl Result {
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

pub trait Matcher: Send + Sync + fmt::Debug {
    fn matches(&self, request: &Packet, response: &Packet) -> Result;

    /// Returns the network-layer source selected for a matched response when
    /// the matcher can identify one. The default preserves compatibility for
    /// matchers that do not expose responder metadata.
    fn responder(&self, _request: &Packet, _response: &Packet) -> Option<IpAddr> {
        None
    }
}
