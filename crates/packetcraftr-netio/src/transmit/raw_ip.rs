// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use crate::interface::Id as InterfaceId;
use crate::{Error, transmit::Layer3Frame};
use packetcraftr_core::protocol::checksum;

pub(crate) const IPV4_MINIMUM_HEADER: usize = 20;
pub(crate) const IPV6_HEADER: usize = 40;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Validated {
    pub(crate) interface: InterfaceId,
    pub(crate) destination: IpAddr,
    pub(crate) bytes: Bytes,
}

pub(crate) fn validate(
    frame: Layer3Frame<'_>,
    target_restrictions: impl FnOnce(&Bytes, IpAddr, IpAddr) -> Result<(), Error>,
) -> Result<Validated, Error> {
    let bytes = frame.bytes().clone();
    let route = frame.route();
    let decision = route.decision;
    if bytes.len() > decision.mtu as usize {
        return Err(invalid_frame(format!(
            "{} bytes exceed route MTU {}",
            bytes.len(),
            decision.mtu
        )));
    }
    if decision.interface.name.is_empty() || decision.interface.index == 0 {
        return Err(invalid_frame(
            "route-selected interface identity is incomplete".to_owned(),
        ));
    }
    let interface_source = decision
        .selected_source
        .or(decision.preferred_source)
        .ok_or_else(|| invalid_frame("route has no interface-owned source address".to_owned()))?;
    let route_destination = route
        .lookup_destination
        .ok_or_else(|| invalid_frame("route has no Layer 3 lookup destination".to_owned()))?;
    let Some(version) = bytes.first().map(|byte| byte >> 4) else {
        return Err(invalid_frame("packet is empty".to_owned()));
    };

    let (packet_source, destination) = match version {
        4 => {
            let (source, destination) = validate_ipv4(&bytes)?;
            (IpAddr::V4(source), IpAddr::V4(destination))
        }
        6 => {
            let (source, destination) = validate_ipv6(&bytes)?;
            (IpAddr::V6(source), IpAddr::V6(destination))
        }
        version => return Err(invalid_frame(format!("unsupported IP version {version}"))),
    };
    if interface_source.is_ipv4() != destination.is_ipv4() {
        return Err(invalid_frame(
            "route-selected source address family differs from packet family".to_owned(),
        ));
    }
    if route_destination != destination {
        return Err(invalid_frame(format!(
            "packet destination {destination} differs from route lookup destination {route_destination}"
        )));
    }
    if packet_source.is_unspecified() {
        return Err(invalid_frame(
            "packet source is unspecified and would be changed by the operating system".to_owned(),
        ));
    }

    target_restrictions(&bytes, packet_source, interface_source)?;

    Ok(Validated {
        interface: decision.interface.clone(),
        destination,
        bytes,
    })
}

fn validate_ipv4(bytes: &[u8]) -> Result<(Ipv4Addr, Ipv4Addr), Error> {
    let header = bytes
        .first_chunk::<IPV4_MINIMUM_HEADER>()
        .ok_or_else(|| invalid_frame("truncated IPv4 header".to_owned()))?;
    let header_length = usize::from(header[0] & 0x0f) * 4;
    if header_length < IPV4_MINIMUM_HEADER || header_length > bytes.len() {
        return Err(invalid_frame(format!(
            "invalid IPv4 header length {header_length}"
        )));
    }
    let declared = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if declared != bytes.len() {
        return Err(invalid_frame(format!(
            "IPv4 total length {declared} differs from submitted {} bytes",
            bytes.len()
        )));
    }
    if header[4..6] == [0, 0] {
        return Err(invalid_frame(
            "IPv4 identification is zero and would be replaced by the operating system".to_owned(),
        ));
    }
    let header_checksum = checksum(&bytes[..header_length]);
    if header_checksum != 0 {
        return Err(invalid_frame(
            "IPv4 header checksum would be rewritten by the operating system".to_owned(),
        ));
    }
    let source = Ipv4Addr::new(header[12], header[13], header[14], header[15]);
    let destination = Ipv4Addr::new(header[16], header[17], header[18], header[19]);
    if destination.is_unspecified() {
        return Err(invalid_frame("IPv4 destination is unspecified".to_owned()));
    }
    Ok((source, destination))
}

fn validate_ipv6(bytes: &[u8]) -> Result<(Ipv6Addr, Ipv6Addr), Error> {
    let header = bytes
        .first_chunk::<IPV6_HEADER>()
        .ok_or_else(|| invalid_frame("truncated IPv6 header".to_owned()))?;
    let actual_payload = bytes.len().saturating_sub(IPV6_HEADER);
    let declared_payload = usize::from(u16::from_be_bytes([header[4], header[5]]));
    if declared_payload != actual_payload {
        return Err(invalid_frame(format!(
            "IPv6 payload length {declared_payload} differs from submitted {actual_payload} bytes"
        )));
    }
    let source = ipv6_address(&header[8..24]);
    let destination = ipv6_address(&header[24..40]);
    if destination.is_unspecified() {
        return Err(invalid_frame("IPv6 destination is unspecified".to_owned()));
    }
    Ok((source, destination))
}

fn ipv6_address(bytes: &[u8]) -> Ipv6Addr {
    let mut address = [0; 16];
    address.copy_from_slice(bytes);
    Ipv6Addr::from(address)
}

pub(crate) fn invalid_frame(message: String) -> Error {
    Error::InvalidTransmissionFrame { message }
}
