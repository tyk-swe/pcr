// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use packetcraftr_network::{
    Error as LiveIoError,
    link::Mode as LinkMode,
    route::{Provider as RouteProvider, SystemProvider as SystemRouteProvider},
    transmit::Report as IoSendReport,
};
use packetcraftr_packet::codec::NetworkEnvelope;
use packetcraftr_packet::error::Kind;
use packetcraftr_packet::frame::{Frame, LinkType};

use super::error::ReplayError;

pub(super) fn map_replay_route_error(
    source: packetcraftr_network::route::SystemError,
) -> LiveIoError {
    let classification = SystemRouteProvider.classify_error(&source);
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
    sequence: u64,
    link_type: LinkType,
    requested: LinkMode,
) -> Result<LinkMode, ReplayError> {
    let supported = match link_type {
        LinkType::ETHERNET => LinkMode::Layer2,
        LinkType::BSD_RAW | LinkType::RAW | LinkType::IPV4 | LinkType::IPV6 => LinkMode::Layer3,
        _ => {
            return Err(ReplayError::UnsupportedLinkType {
                sequence,
                link_type: link_type.0,
            });
        }
    };
    match requested {
        LinkMode::Auto => Ok(supported),
        requested if requested == supported => Ok(requested),
        requested => Err(ReplayError::LinkModeMismatch {
            sequence,
            link_type: link_type.0,
            requested,
        }),
    }
}

pub(super) fn validate_transmission_evidence(
    sequence: u64,
    frame: &Frame,
    report: &IoSendReport,
) -> Result<(), ReplayError> {
    if report.bytes_sent() != frame.bytes().len() {
        return Err(ReplayError::Transmission {
            sequence,
            source: LiveIoError::PartialSend {
                expected: frame.bytes().len(),
                actual: report.bytes_sent(),
            },
        });
    }
    if report.wire_bytes() != frame.bytes() {
        return Err(ReplayError::InvalidEvidence {
            sequence,
            message: format!(
                "backend returned {} wire bytes that differ from the {} submitted bytes",
                report.wire_bytes().len(),
                frame.bytes().len()
            ),
        });
    }
    Ok(())
}
