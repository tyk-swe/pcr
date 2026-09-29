// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::ops::Range;
use std::time::Duration;

use packetcraftr_core::capture_file::Interface;
use packetcraftr_core::codec::NetworkEnvelope;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::headers::{Ipv4Header, Ipv6Header};
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmission {
    pub interface: InterfaceId,
    pub report: IoSendReport,
}

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
        4 => bytes
            .get(..Ipv4Header::MIN_LENGTH)
            .and_then(|header| {
                Some(NetworkEnvelope {
                    source: IpAddr::V4(octets::<4>(header, Ipv4Header::SOURCE)?.into()),
                    destination: IpAddr::V4(octets::<4>(header, Ipv4Header::DESTINATION)?.into()),
                })
            })
            .ok_or_else(|| invalid("replay frame has a truncated IPv4 header".to_owned())),
        6 => bytes
            .get(..Ipv6Header::LENGTH)
            .and_then(|header| {
                Some(NetworkEnvelope {
                    source: IpAddr::V6(octets::<16>(header, Ipv6Header::SOURCE)?.into()),
                    destination: IpAddr::V6(octets::<16>(header, Ipv6Header::DESTINATION)?.into()),
                })
            })
            .ok_or_else(|| invalid("replay frame has a truncated IPv6 header".to_owned())),
        value => Err(invalid(format!(
            "replay frame has unsupported IP version {value}"
        ))),
    }
}

fn octets<const N: usize>(bytes: &[u8], range: Range<usize>) -> Option<[u8; N]> {
    bytes.get(range)?.try_into().ok()
}

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
