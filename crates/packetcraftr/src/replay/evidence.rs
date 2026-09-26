// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! What a replay observed: the captured frame's own envelope, and the exact
//! bytes a provider confirmed it sent.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use packetcraftr_core::capture_file::Interface;
use packetcraftr_core::codec::NetworkEnvelope;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_netio::{
    Error as LiveIoError, interface::Id as InterfaceId, link::Mode as LinkMode,
    transmit::Report as IoSendReport,
};

use super::error::Error;

/// Per-frame evidence published only after exact transmission is confirmed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameEvidence {
    /// One-based pass identity; source_index remains relative to the input capture.
    pub pass: u32,
    pub source_index: u64,
    pub source_interface_id: Option<u32>,
    pub capture_interface: Interface,
    pub link_mode: LinkMode,
    pub scheduled_delay: Duration,
    pub frame: Frame,
    pub(super) transmission: Transmission,
}

impl FrameEvidence {
    pub fn transmission(&self) -> &Transmission {
        &self.transmission
    }
}

/// Exact provider report plus the concrete interface selected for a send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmission {
    pub interface: InterfaceId,
    pub report: IoSendReport,
}

/// The source and destination of a raw IP frame, read from its own header.
pub(super) fn network_envelope(frame: &Frame) -> Result<NetworkEnvelope, LiveIoError> {
    let invalid = |message: String| LiveIoError::InvalidTransmissionFrame { message };
    let bytes = frame.bytes().as_ref();
    let Some(version) = bytes.first().map(|byte| byte >> 4) else {
        return Err(invalid("replay frame is empty".to_owned()));
    };
    match (frame.link_type, version) {
        (LinkType::IPV4, actual) if actual != 4 => {
            return Err(invalid(format!(
                "capture link type {} declares IPv4 but the frame contains IP version {actual}",
                frame.link_type.0
            )));
        }
        (LinkType::IPV6, actual) if actual != 6 => {
            return Err(invalid(format!(
                "capture link type {} declares IPv6 but the frame contains IP version {actual}",
                frame.link_type.0
            )));
        }
        _ => {}
    }
    match version {
        4 if bytes.len() >= 20 => {
            let source: [u8; 4] = bytes
                .get(12..16)
                .and_then(|octets| octets.try_into().ok())
                .ok_or_else(|| invalid("replay frame has a truncated IPv4 header".to_owned()))?;
            let destination: [u8; 4] = bytes
                .get(16..20)
                .and_then(|octets| octets.try_into().ok())
                .ok_or_else(|| invalid("replay frame has a truncated IPv4 header".to_owned()))?;
            Ok(NetworkEnvelope {
                source: IpAddr::V4(Ipv4Addr::from(source)),
                destination: IpAddr::V4(Ipv4Addr::from(destination)),
            })
        }
        6 if bytes.len() >= 40 => {
            let source: [u8; 16] = bytes
                .get(8..24)
                .and_then(|octets| octets.try_into().ok())
                .ok_or_else(|| invalid("replay frame has a truncated IPv6 header".to_owned()))?;
            let destination: [u8; 16] = bytes
                .get(24..40)
                .and_then(|octets| octets.try_into().ok())
                .ok_or_else(|| invalid("replay frame has a truncated IPv6 header".to_owned()))?;
            Ok(NetworkEnvelope {
                source: IpAddr::V6(Ipv6Addr::from(source)),
                destination: IpAddr::V6(Ipv6Addr::from(destination)),
            })
        }
        4 => Err(invalid(
            "replay frame has a truncated IPv4 header".to_owned(),
        )),
        6 => Err(invalid(
            "replay frame has a truncated IPv6 header".to_owned(),
        )),
        value => Err(invalid(format!(
            "replay frame has unsupported IP version {value}"
        ))),
    }
}

/// Requires the provider to confirm exactly the frame's bytes.
pub(super) fn validate_transmission(
    source_index: u64,
    frame: &Frame,
    report: &IoSendReport,
) -> Result<(), Error> {
    report
        .validate_exact(frame.bytes())
        .map_err(|source| Error::Transmission {
            source_index,
            source,
        })
}
