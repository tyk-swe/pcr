// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Pure raw-IP validation and target-specific byte preparation.

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use super::super::super::{Error as LiveIoError, transmit::Layer3Frame};
use crate::route::InterfaceId;

const IPV4_MINIMUM_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IpFamily {
    V4,
    V6,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PreparedRawIp {
    pub(super) family: IpFamily,
    pub(super) interface: InterfaceId,
    pub(super) interface_source: IpAddr,
    pub(super) destination: IpAddr,
    pub(super) submission: Bytes,
    pub(super) wire_bytes: Bytes,
}

pub(super) fn prepare(frame: Layer3Frame<'_>) -> Result<PreparedRawIp, LiveIoError> {
    let bytes = frame.bytes().clone();
    let plan = &frame.route().plan;
    if bytes.len() > plan.route.mtu as usize {
        return Err(invalid_frame(format!(
            "{} bytes exceed route MTU {}",
            bytes.len(),
            plan.route.mtu
        )));
    }
    if plan.route.interface.name.is_empty() || plan.route.interface.index == 0 {
        return Err(invalid_frame(
            "route-selected interface identity is incomplete".to_owned(),
        ));
    }
    let interface_source = plan
        .route
        .selected_address
        .or(plan.route.preferred_source)
        .ok_or_else(|| invalid_frame("route has no interface-owned source address".to_owned()))?;
    let route_destination = plan
        .lookup_destination
        .ok_or_else(|| invalid_frame("route has no Layer 3 lookup destination".to_owned()))?;
    let Some(version) = bytes.first().map(|byte| byte >> 4) else {
        return Err(invalid_frame("packet is empty".to_owned()));
    };

    let (family, packet_source, destination, submission) = match version {
        4 => {
            let (source, destination) = validate_ipv4(&bytes)?;
            (
                IpFamily::V4,
                IpAddr::V4(source),
                IpAddr::V4(destination),
                ipv4_submission(&bytes),
            )
        }
        6 => {
            let (source, destination) = validate_ipv6(&bytes)?;
            (
                IpFamily::V6,
                IpAddr::V6(source),
                IpAddr::V6(destination),
                bytes.clone(),
            )
        }
        version => return Err(invalid_frame(format!("unsupported IP version {version}"))),
    };
    if interface_source.is_ipv4() != matches!(family, IpFamily::V4) {
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

    #[cfg(windows)]
    validate_windows_restrictions(&bytes, packet_source, interface_source)?;

    Ok(PreparedRawIp {
        family,
        interface: plan.route.interface.clone(),
        interface_source,
        destination,
        submission,
        wire_bytes: bytes,
    })
}

fn validate_ipv4(bytes: &[u8]) -> Result<(Ipv4Addr, Ipv4Addr), LiveIoError> {
    if bytes.len() < IPV4_MINIMUM_HEADER {
        return Err(invalid_frame("truncated IPv4 header".to_owned()));
    }
    let header_length = usize::from(bytes[0] & 0x0f) * 4;
    if header_length < IPV4_MINIMUM_HEADER || header_length > bytes.len() {
        return Err(invalid_frame(format!(
            "invalid IPv4 header length {header_length}"
        )));
    }
    let declared = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if declared != bytes.len() {
        return Err(invalid_frame(format!(
            "IPv4 total length {declared} differs from submitted {} bytes",
            bytes.len()
        )));
    }
    if bytes[4..6] == [0, 0] {
        return Err(invalid_frame(
            "IPv4 identification is zero and would be replaced by the operating system".to_owned(),
        ));
    }
    if checksum(&bytes[..header_length]) != 0 {
        return Err(invalid_frame(
            "IPv4 header checksum would be rewritten by the operating system".to_owned(),
        ));
    }
    let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    if destination.is_unspecified() {
        return Err(invalid_frame("IPv4 destination is unspecified".to_owned()));
    }
    Ok((source, destination))
}

fn validate_ipv6(bytes: &[u8]) -> Result<(Ipv6Addr, Ipv6Addr), LiveIoError> {
    if bytes.len() < IPV6_HEADER {
        return Err(invalid_frame("truncated IPv6 header".to_owned()));
    }
    let actual_payload = bytes.len() - IPV6_HEADER;
    let declared_payload = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    if declared_payload != actual_payload {
        return Err(invalid_frame(format!(
            "IPv6 payload length {declared_payload} differs from submitted {actual_payload} bytes"
        )));
    }
    let source = ipv6_address(&bytes[8..24]);
    let destination = ipv6_address(&bytes[24..40]);
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

#[cfg(target_os = "macos")]
fn ipv4_submission(bytes: &Bytes) -> Bytes {
    macos_ipv4_submission(bytes)
}

#[cfg(not(target_os = "macos"))]
fn ipv4_submission(bytes: &Bytes) -> Bytes {
    bytes.clone()
}

#[cfg(any(test, target_os = "macos"))]
pub(super) fn macos_ipv4_submission(bytes: &Bytes) -> Bytes {
    let mut submission = bytes.to_vec();
    let total_length = u16::from_be_bytes([submission[2], submission[3]]);
    submission[2..4].copy_from_slice(&total_length.to_ne_bytes());
    let flags_and_offset = u16::from_be_bytes([submission[6], submission[7]]);
    submission[6..8].copy_from_slice(&flags_and_offset.to_ne_bytes());
    Bytes::from(submission)
}

#[cfg(windows)]
fn validate_windows_restrictions(
    bytes: &[u8],
    packet_source: IpAddr,
    interface_source: IpAddr,
) -> Result<(), LiveIoError> {
    let protocol = upper_protocol(bytes)?;
    if protocol == 17 && packet_source != interface_source {
        return Err(LiveIoError::Unsupported {
            message: "Windows client editions drop raw UDP with a source not assigned to a local interface"
                .to_owned(),
        });
    }
    Ok(())
}

#[cfg(any(test, windows))]
pub(super) fn upper_protocol(bytes: &[u8]) -> Result<u8, LiveIoError> {
    if bytes[0] >> 4 == 4 {
        return Ok(bytes[9]);
    }
    let mut next = bytes[6];
    let mut offset = IPV6_HEADER;
    loop {
        let header_length = match next {
            0 | 43 | 60 => {
                let header = bytes
                    .get(offset..offset + 2)
                    .ok_or_else(|| invalid_frame("truncated IPv6 extension header".to_owned()))?;
                next = header[0];
                usize::from(header[1])
                    .checked_add(1)
                    .and_then(|units| units.checked_mul(8))
                    .ok_or_else(|| invalid_frame("IPv6 extension length overflowed".to_owned()))?
            }
            44 => {
                next = *bytes
                    .get(offset)
                    .ok_or_else(|| invalid_frame("truncated IPv6 fragment header".to_owned()))?;
                8
            }
            51 => {
                let header = bytes.get(offset..offset + 2).ok_or_else(|| {
                    invalid_frame("truncated IPv6 authentication header".to_owned())
                })?;
                next = header[0];
                usize::from(header[1])
                    .checked_add(2)
                    .and_then(|units| units.checked_mul(4))
                    .ok_or_else(|| {
                        invalid_frame("IPv6 authentication length overflowed".to_owned())
                    })?
            }
            _ => return Ok(next),
        };
        offset = offset
            .checked_add(header_length)
            .filter(|offset| *offset <= bytes.len())
            .ok_or_else(|| invalid_frame("IPv6 extension exceeds packet bytes".to_owned()))?;
    }
}

#[cfg(test)]
pub(super) fn checksum(bytes: &[u8]) -> u16 {
    checksum_impl(bytes)
}

#[cfg(not(test))]
fn checksum(bytes: &[u8]) -> u16 {
    checksum_impl(bytes)
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "the fold loop only exits once sum >> 16 is zero, so sum is at most 0xffff"
)]
fn checksum_impl(bytes: &[u8]) -> u16 {
    let mut sum = 0_u64;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u64::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(byte) = chunks.remainder().first() {
        sum += u64::from(u16::from_be_bytes([*byte, 0]));
    }
    while sum > u64::from(u16::MAX) {
        sum = (sum & u64::from(u16::MAX)) + (sum >> 16);
    }
    !(sum as u16)
}

fn invalid_frame(message: String) -> LiveIoError {
    LiveIoError::InvalidTransmissionFrame { message }
}
