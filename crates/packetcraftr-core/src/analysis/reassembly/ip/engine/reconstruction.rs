// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact network-header reconstruction after a complete payload is admitted.

use super::{
    Bytes, Ecn, Error, Family, IPV6_HEADER_LENGTH, MalformedError, Reconstruction, ResourceError,
};

/// A complete IPv4 datagram covers offset zero, so the fragment that filled
/// it recorded the header every reconstruction needs.
const MISSING_OFFSET_ZERO_HEADER: Error = Error::Inconsistent {
    reason: "complete IPv4 payload has no offset-zero header",
};
/// Wire length of the datagram a complete payload of `payload_length` bytes
/// reconstructs to, including the retained header or prefix.
pub(super) fn reconstructed_length(
    reconstruction: &Reconstruction,
    payload_length: usize,
) -> Result<usize, Error> {
    let prefix = match reconstruction {
        Reconstruction::Ipv4 { first_header, .. } => first_header
            .as_ref()
            .map(Bytes::len)
            .ok_or(MISSING_OFFSET_ZERO_HEADER)?,
        Reconstruction::Ipv6 { prefix, .. } => prefix.len(),
    };
    prefix
        .checked_add(payload_length)
        .ok_or(MalformedError::OffsetOverflow.into())
}

/// Reconstructs the datagram from its complete payload, given as up to two
/// consecutive slices so a completing append need not be stored first.
pub(super) fn reconstruct_bytes(
    reconstruction: &Reconstruction,
    payload: [&[u8]; 2],
) -> Result<Bytes, Error> {
    match reconstruction {
        Reconstruction::Ipv4 { first_header, ecn } => {
            reconstruct_ipv4(first_header.as_ref(), *ecn, payload)
        }
        Reconstruction::Ipv6 {
            prefix,
            predecessor_next_header_offset,
            next_header,
            ecn,
            ..
        } => reconstruct_ipv6(
            prefix,
            *predecessor_next_header_offset,
            *next_header,
            *ecn,
            payload,
        ),
    }
}

fn payload_length(payload: [&[u8]; 2]) -> Result<usize, Error> {
    payload
        .iter()
        .try_fold(0usize, |total, part| total.checked_add(part.len()))
        .ok_or(MalformedError::OffsetOverflow.into())
}

fn reconstruct_ipv4(
    first_header: Option<&Bytes>,
    ecn: Ecn,
    payload: [&[u8]; 2],
) -> Result<Bytes, Error> {
    let header = first_header.ok_or(MISSING_OFFSET_ZERO_HEADER)?;
    let payload_length = payload_length(payload)?;
    let total_length = header
        .len()
        .checked_add(payload_length)
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(MalformedError::ReconstructedLength {
            family: Family::Ipv4,
        })?;
    let mut datagram = Vec::new();
    let requested = usize::from(total_length);
    datagram
        .try_reserve_exact(requested)
        .map_err(|_| ResourceError::AllocationFailed { requested })?;
    datagram.extend_from_slice(header);
    for part in payload {
        datagram.extend_from_slice(part);
    }
    datagram
        .get_mut(2..4)
        .ok_or(MalformedError::OffsetOverflow)?
        .copy_from_slice(&total_length.to_be_bytes());
    let tos = datagram.get_mut(1).ok_or(MalformedError::OffsetOverflow)?;
    *tos = (*tos & 0xfc) | ecn.ipv4_tos_bits();
    let flags = datagram
        .get(6..8)
        .and_then(<[u8]>::first_chunk::<2>)
        .copied()
        .map(u16::from_be_bytes)
        .ok_or(MalformedError::OffsetOverflow)?
        & 0xc000;
    datagram
        .get_mut(6..8)
        .ok_or(MalformedError::OffsetOverflow)?
        .copy_from_slice(&flags.to_be_bytes());
    datagram
        .get_mut(10..12)
        .ok_or(MalformedError::OffsetOverflow)?
        .fill(0);
    let checksum = crate::protocol::checksum(
        datagram
            .get(..header.len())
            .ok_or(MalformedError::OffsetOverflow)?,
    );
    datagram
        .get_mut(10..12)
        .ok_or(MalformedError::OffsetOverflow)?
        .copy_from_slice(&checksum.to_be_bytes());
    Ok(Bytes::from(datagram))
}

fn reconstruct_ipv6(
    prefix: &Bytes,
    predecessor_next_header_offset: usize,
    next_header: u8,
    ecn: Ecn,
    payload: [&[u8]; 2],
) -> Result<Bytes, Error> {
    let extension_length = prefix
        .len()
        .checked_sub(IPV6_HEADER_LENGTH)
        .ok_or(MalformedError::OffsetOverflow)?;
    let payload_bytes = payload_length(payload)?;
    let payload_length = extension_length
        .checked_add(payload_bytes)
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(MalformedError::ReconstructedLength {
            family: Family::Ipv6,
        })?;
    let requested = prefix
        .len()
        .checked_add(payload_bytes)
        .ok_or(MalformedError::OffsetOverflow)?;
    let mut datagram = Vec::new();
    datagram
        .try_reserve_exact(requested)
        .map_err(|_| ResourceError::AllocationFailed { requested })?;
    datagram.extend_from_slice(prefix);
    for part in payload {
        datagram.extend_from_slice(part);
    }
    datagram
        .get_mut(4..6)
        .ok_or(MalformedError::OffsetOverflow)?
        .copy_from_slice(&payload_length.to_be_bytes());
    let traffic_class = datagram.get_mut(1).ok_or(MalformedError::OffsetOverflow)?;
    *traffic_class = (*traffic_class & !0x30) | ecn.ipv6_traffic_class_bits();
    *datagram
        .get_mut(predecessor_next_header_offset)
        .ok_or(MalformedError::OffsetOverflow)? = next_header;
    Ok(Bytes::from(datagram))
}
