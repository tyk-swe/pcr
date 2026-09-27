// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The target's part of preparing a raw IP send: the datagram is validated by
//! `transmit::raw_ip`, then this target adds what its raw sockets refuse
//! (Windows drops raw UDP from a foreign source) and rewrites the bytes it
//! submits (macOS reads two IPv4 header fields in host byte order).

use std::net::IpAddr;

use bytes::Bytes;

use crate::interface::Id as InterfaceId;
use crate::transmit::raw_ip::{Validated, validate};
use crate::{Error, transmit::Layer3Frame};
#[cfg(target_os = "windows")]
use crate::{NativeCapability, Unsupported, link::Mode};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::platform) struct PreparedRawIp {
    pub(in crate::platform) interface: InterfaceId,
    pub(in crate::platform) destination: IpAddr,
    /// The bytes handed to the socket, which may differ from `wire_bytes`
    /// only where the target's socket ABI reads a header field differently.
    pub(in crate::platform) submission: Bytes,
    pub(in crate::platform) wire_bytes: Bytes,
}

pub(in crate::platform) fn prepare(frame: Layer3Frame<'_>) -> Result<PreparedRawIp, Error> {
    let Validated {
        interface,
        destination,
        bytes,
    } = validate(frame, target_restrictions)?;
    let submission = match destination {
        IpAddr::V4(_) => ipv4_submission(&bytes)?,
        IpAddr::V6(_) => bytes.clone(),
    };
    Ok(PreparedRawIp {
        interface,
        destination,
        submission,
        wire_bytes: bytes,
    })
}

#[cfg(target_os = "macos")]
fn ipv4_submission(bytes: &Bytes) -> Result<Bytes, Error> {
    macos_ipv4_submission(bytes)
}

#[cfg(not(target_os = "macos"))]
fn ipv4_submission(bytes: &Bytes) -> Result<Bytes, Error> {
    Ok(bytes.clone())
}

/// Rewrites the two header fields the macOS raw IPv4 socket expects in host byte
/// order. Callers must validate the packet first: a buffer shorter than the
/// minimum header is rejected instead of being sent with big-endian fields the
/// kernel would misread.
#[cfg(target_os = "macos")]
fn macos_ipv4_submission(bytes: &Bytes) -> Result<Bytes, Error> {
    use crate::transmit::raw_ip::{IPV4_MINIMUM_HEADER, invalid_frame};

    let mut submission = bytes.to_vec();
    let Some(header) = submission.first_chunk_mut::<IPV4_MINIMUM_HEADER>() else {
        return Err(invalid_frame("truncated IPv4 header".to_owned()));
    };
    let total_length = u16::from_be_bytes([header[2], header[3]]);
    header[2..4].copy_from_slice(&total_length.to_ne_bytes());
    let flags_and_offset = u16::from_be_bytes([header[6], header[7]]);
    header[6..8].copy_from_slice(&flags_and_offset.to_ne_bytes());
    Ok(Bytes::from(submission))
}

/// Linux and macOS raw sockets send any validated datagram.
#[cfg(not(target_os = "windows"))]
fn target_restrictions(
    _bytes: &Bytes,
    _packet_source: IpAddr,
    _interface_source: IpAddr,
) -> Result<(), Error> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn target_restrictions(
    bytes: &Bytes,
    packet_source: IpAddr,
    interface_source: IpAddr,
) -> Result<(), Error> {
    let protocol = upper_protocol(bytes)?;
    if protocol == 17 && packet_source != interface_source {
        return Err(Unsupported::new(
            NativeCapability::Transmission(Mode::Layer3),
            "Windows client editions drop raw UDP with a source not assigned to a local interface",
        )
        .into());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn extension_header(bytes: &[u8], offset: usize) -> Option<[u8; 2]> {
    bytes.get(offset..)?.first_chunk::<2>().copied()
}

#[cfg(target_os = "windows")]
fn upper_protocol(bytes: &[u8]) -> Result<u8, Error> {
    use crate::transmit::raw_ip::{IPV6_HEADER, invalid_frame};

    let version = bytes
        .first()
        .ok_or_else(|| invalid_frame("packet is empty".to_owned()))?;
    if version >> 4 == 4 {
        return bytes
            .get(9)
            .copied()
            .ok_or_else(|| invalid_frame("truncated IPv4 header".to_owned()));
    }
    let mut next = *bytes
        .get(6)
        .ok_or_else(|| invalid_frame("truncated IPv6 header".to_owned()))?;
    let mut offset = IPV6_HEADER;
    loop {
        let header_length = match next {
            0 | 43 | 60 => {
                let header = extension_header(bytes, offset)
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
                let header = extension_header(bytes, offset).ok_or_else(|| {
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
