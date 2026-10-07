// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Scan method selection. An explicit method is never replaced; automatic
//! selection is opt-in and publishes why it chose what it chose.
//!
//! Selection never fails for a missing packet capability: the raw engine
//! reports that after policy review, so a denial reads the same in every
//! build.

use packetcraftr_netio::Unsupported;

use super::Error;
use crate::probe::{ProbeEndpoint, Transport};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Method {
    /// Crafted probes correlated with captured replies: TCP SYN, UDP, and
    /// ICMP echo.
    Raw,
    /// Kernel TCP connections, observed as socket outcomes rather than wire
    /// evidence.
    Connect,
}

impl Method {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Connect => "tcp_connect",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Requested {
    #[default]
    Raw,
    Connect,
    Automatic,
}

impl Requested {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Connect => "tcp_connect",
            Self::Automatic => "automatic",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    pub requested: Requested,
    pub method: Method,
    /// Why automatic selection chose `method`; absent for explicit requests.
    pub reason: Option<String>,
}

/// What the build and the request leave available to the selection.
#[derive(Clone, Debug)]
pub struct Capabilities {
    /// `Ok` when this build can capture and transmit crafted packets.
    pub raw: Result<(), Unsupported>,
    /// Whether the request pins a packet interface, source, or link, which a
    /// kernel connection cannot honor.
    pub packet_route: bool,
}

pub fn select(
    requested: Requested,
    endpoints: &[ProbeEndpoint],
    capabilities: Capabilities,
) -> Result<Selection, Error> {
    let Capabilities { raw, packet_route } = capabilities;
    let explicit = |method| Selection {
        requested,
        method,
        reason: None,
    };
    match requested {
        Requested::Raw => Ok(explicit(Method::Raw)),
        Requested::Connect => {
            if let Some(transport) = unconnectable(endpoints) {
                return Err(Error::MethodTransport {
                    method: Method::Connect.as_str(),
                    transport: transport.as_str(),
                });
            }
            if packet_route {
                return Err(Error::UnsupportedTcpRoute);
            }
            Ok(explicit(Method::Connect))
        }
        Requested::Automatic => {
            let (method, reason) = match (raw, unconnectable(endpoints)) {
                (Ok(()), _) => (
                    Method::Raw,
                    "this build captures and transmits crafted packets".to_owned(),
                ),
                (Err(source), None) if !packet_route => (
                    Method::Connect,
                    format!(
                        "{source}; every endpoint is TCP, which an ordinary connection can probe"
                    ),
                ),
                (Err(source), None) => (
                    Method::Raw,
                    format!("{source}; only the raw method can use the requested packet route"),
                ),
                (Err(source), Some(transport)) => (
                    Method::Raw,
                    format!("{source}; only the raw method can probe {transport} endpoints"),
                ),
            };
            Ok(Selection {
                requested,
                method,
                reason: Some(reason),
            })
        }
    }
}

/// The first endpoint transport an ordinary TCP connection cannot probe.
fn unconnectable(endpoints: &[ProbeEndpoint]) -> Option<Transport> {
    endpoints
        .iter()
        .map(|endpoint| endpoint.transport())
        .find(|transport| *transport != Transport::Tcp)
}

#[cfg(test)]
mod tests;
