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

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const DESTINATION_V4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);

    fn valid_ipv4() -> Vec<u8> {
        let mut bytes = vec![0_u8; IPV4_MINIMUM_HEADER];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(
            &u16::try_from(IPV4_MINIMUM_HEADER)
                .expect("IPv4 header length fits u16")
                .to_be_bytes(),
        );
        bytes[4..6].copy_from_slice(&1_u16.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&SOURCE_V4.octets());
        bytes[16..20].copy_from_slice(&DESTINATION_V4.octets());
        set_ipv4_checksum(&mut bytes);
        bytes
    }

    fn set_ipv4_checksum(bytes: &mut [u8]) {
        bytes[10..12].fill(0);
        let checksum = checksum(bytes);
        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    }

    fn valid_ipv6() -> Vec<u8> {
        let source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let mut bytes = vec![0_u8; IPV6_HEADER + 4];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&4_u16.to_be_bytes());
        bytes[6] = 17;
        bytes[7] = 64;
        bytes[8..24].copy_from_slice(&source.octets());
        bytes[24..40].copy_from_slice(&destination.octets());
        bytes
    }

    fn invalid_message<T: std::fmt::Debug>(result: Result<T, Error>) -> String {
        match result.expect_err("fixture must be rejected") {
            Error::InvalidTransmissionFrame { message } => message,
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn ipv4_validation_rejects_each_field_the_kernel_might_rewrite() {
        assert_eq!(
            validate_ipv4(&valid_ipv4()).expect("valid datagram"),
            (SOURCE_V4, DESTINATION_V4)
        );

        let mut invalid = Vec::new();
        invalid.push(("truncated IPv4 header", vec![0x45; IPV4_MINIMUM_HEADER - 1]));

        let mut header = valid_ipv4();
        header[0] = 0x44;
        invalid.push(("invalid IPv4 header length", header));

        let mut header = valid_ipv4();
        header[2..4].copy_from_slice(&21_u16.to_be_bytes());
        invalid.push(("IPv4 total length", header));

        let mut header = valid_ipv4();
        header[4..6].fill(0);
        invalid.push(("IPv4 identification is zero", header));

        let mut header = valid_ipv4();
        header[8] ^= 1;
        invalid.push(("IPv4 header checksum", header));

        let mut header = valid_ipv4();
        header[16..20].fill(0);
        set_ipv4_checksum(&mut header);
        invalid.push(("IPv4 destination is unspecified", header));

        for (expected, bytes) in invalid {
            assert!(
                invalid_message(validate_ipv4(&bytes)).contains(expected),
                "expected diagnostic containing {expected}"
            );
        }
    }

    #[test]
    fn ipv6_validation_requires_an_exact_complete_datagram() {
        let bytes = valid_ipv6();
        let expected_source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let expected_destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        assert_eq!(
            validate_ipv6(&bytes).expect("valid datagram"),
            (expected_source, expected_destination)
        );

        assert!(invalid_message(validate_ipv6(&bytes[..39])).contains("truncated IPv6 header"));

        let mut invalid_length = bytes.clone();
        invalid_length[4..6].copy_from_slice(&3_u16.to_be_bytes());
        assert!(invalid_message(validate_ipv6(&invalid_length)).contains("IPv6 payload length"));

        let mut unspecified = bytes;
        unspecified[24..40].fill(0);
        assert!(
            invalid_message(validate_ipv6(&unspecified))
                .contains("IPv6 destination is unspecified")
        );
    }
}
