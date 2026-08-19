// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use packetcraftr_core::codec::NetworkEnvelope;
use packetcraftr_core::error::Kind;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_netio::route::Provider;
use packetcraftr_netio::{
    Error as LiveIoError, link::Mode as LinkMode, transmit::Report as IoSendReport,
};

use super::error::Error;

pub(super) fn map_replay_route_error(
    source: packetcraftr_netio::route::SystemError,
) -> LiveIoError {
    let classification = packetcraftr_netio::route::SystemProvider.classify_error(&source);
    match classification.kind {
        Kind::Capability => LiveIoError::Unsupported {
            message: source.to_string(),
        },
        _ => LiveIoError::Send {
            message: format!("replay route selection failed: {source}"),
        },
    }
}

pub(super) fn replay_network_envelope(frame: &Frame) -> Result<NetworkEnvelope, LiveIoError> {
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
            let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
            let destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
            Ok(NetworkEnvelope {
                source: IpAddr::V4(source),
                destination: IpAddr::V4(destination),
            })
        }
        6 if bytes.len() >= 40 => {
            let mut source = [0_u8; 16];
            let mut destination = [0_u8; 16];
            source.copy_from_slice(&bytes[8..24]);
            destination.copy_from_slice(&bytes[24..40]);
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

pub(super) fn replay_link_mode(
    source_index: u64,
    link_type: LinkType,
    requested: LinkMode,
) -> Result<LinkMode, Error> {
    let supported = match link_type {
        LinkType::ETHERNET => LinkMode::Layer2,
        LinkType::BSD_RAW | LinkType::RAW | LinkType::IPV4 | LinkType::IPV6 => LinkMode::Layer3,
        _ => {
            return Err(Error::UnsupportedLinkType {
                source_index,
                link_type: link_type.0,
            });
        }
    };
    match requested {
        LinkMode::Auto => Ok(supported),
        requested if requested == supported => Ok(requested),
        requested => Err(Error::LinkModeMismatch {
            source_index,
            link_type: link_type.0,
            requested,
        }),
    }
}

pub(super) fn validate_transmission_evidence(
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
