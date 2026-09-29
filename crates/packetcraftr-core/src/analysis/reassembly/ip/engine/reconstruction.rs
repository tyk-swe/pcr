// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::validation::{FAMILY_MISMATCH, Incoming, IncomingReconstruction};
use super::{Bytes, DatagramState, Ecn, Error, Family, Malformed, Reconstruction, Resource};
use crate::protocol::headers::Ipv6Header;

const MISSING_OFFSET_ZERO_HEADER: Error = Error::Inconsistent {
    reason: "complete IPv4 payload has no offset-zero header",
};
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
        .ok_or(Malformed::OffsetOverflow.into())
}

/// The payload is up to two consecutive slices so a completing append need not be stored first.
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

enum RetainedHeader<'a> {
    /// An IPv4 fragment away from offset zero arrived first, so no header exists yet.
    Absent,
    Established(&'a Reconstruction),
    Incoming,
}

impl RetainedHeader<'_> {
    fn len(&self, incoming: &Incoming) -> usize {
        match self {
            Self::Absent => 0,
            Self::Established(Reconstruction::Ipv4 { first_header, .. }) => {
                first_header.as_ref().map_or(0, Bytes::len)
            }
            Self::Established(Reconstruction::Ipv6 { prefix, .. }) => prefix.len(),
            Self::Incoming => match &incoming.reconstruction {
                IncomingReconstruction::Ipv4 { header } => header.len(),
                IncomingReconstruction::Ipv6 { prefix, .. } => prefix.len(),
            },
        }
    }
}

/// IPv4 keeps the first offset-zero header. IPv6 keeps the first prefix until the offset-zero
/// fragment supplies its own (RFC 8200 §4.5).
fn retained_header<'a>(
    existing: Option<&'a DatagramState>,
    incoming: &Incoming,
) -> Result<RetainedHeader<'a>, Error> {
    let Some(state) = existing else {
        return Ok(match &incoming.reconstruction {
            IncomingReconstruction::Ipv4 { .. } if incoming.offset != 0 => RetainedHeader::Absent,
            _ => RetainedHeader::Incoming,
        });
    };
    let provisional = match (&state.reconstruction, &incoming.reconstruction) {
        (Reconstruction::Ipv4 { first_header, .. }, IncomingReconstruction::Ipv4 { .. }) => {
            first_header.is_none()
        }
        (
            Reconstruction::Ipv6 {
                from_offset_zero, ..
            },
            IncomingReconstruction::Ipv6 { .. },
        ) => !from_offset_zero,
        _ => return Err(FAMILY_MISMATCH),
    };
    Ok(if provisional && incoming.offset == 0 {
        RetainedHeader::Incoming
    } else {
        RetainedHeader::Established(&state.reconstruction)
    })
}

pub(super) fn reconstruction_retained_bytes(
    existing: Option<&DatagramState>,
    incoming: &Incoming,
) -> Result<usize, Error> {
    Ok(retained_header(existing, incoming)?.len(incoming))
}

pub(super) fn reconstruction_copied_bytes(
    existing: Option<&DatagramState>,
    incoming: &Incoming,
) -> usize {
    match retained_header(existing, incoming) {
        Ok(header @ RetainedHeader::Incoming) => header.len(incoming),
        Ok(RetainedHeader::Absent | RetainedHeader::Established(_)) | Err(_) => 0,
    }
}

pub(super) fn materialize_reconstruction(
    existing: Option<&DatagramState>,
    incoming: &Incoming,
    ecn: Ecn,
) -> Result<Reconstruction, Error> {
    let retained = retained_header(existing, incoming)?;
    Ok(match (retained, &incoming.reconstruction) {
        (RetainedHeader::Established(established), _) => {
            let mut reconstruction = established.clone();
            match &mut reconstruction {
                Reconstruction::Ipv4 { ecn: merged, .. }
                | Reconstruction::Ipv6 { ecn: merged, .. } => *merged = ecn,
            }
            reconstruction
        }
        (RetainedHeader::Absent, _) => Reconstruction::Ipv4 {
            first_header: None,
            ecn,
        },
        (RetainedHeader::Incoming, IncomingReconstruction::Ipv4 { header }) => {
            Reconstruction::Ipv4 {
                first_header: Some(copy_bytes(header)?),
                ecn,
            }
        }
        (
            RetainedHeader::Incoming,
            IncomingReconstruction::Ipv6 {
                prefix,
                predecessor_next_header_offset,
                next_header,
            },
        ) => Reconstruction::Ipv6 {
            prefix: copy_bytes(prefix)?,
            predecessor_next_header_offset: *predecessor_next_header_offset,
            next_header: *next_header,
            ecn,
            from_offset_zero: incoming.offset == 0,
        },
    })
}

fn copy_bytes(source: &[u8]) -> Result<Bytes, Error> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(source.len())
        .map_err(|_| Resource::AllocationFailed {
            requested: source.len(),
        })?;
    copy.extend_from_slice(source);
    Ok(Bytes::from(copy))
}

fn payload_length(payload: [&[u8]; 2]) -> Result<usize, Error> {
    payload
        .iter()
        .try_fold(0usize, |total, part| total.checked_add(part.len()))
        .ok_or(Malformed::OffsetOverflow.into())
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
        .ok_or(Malformed::ReconstructedLength {
            family: Family::Ipv4,
        })?;
    let mut datagram = Vec::new();
    let requested = usize::from(total_length);
    datagram
        .try_reserve_exact(requested)
        .map_err(|_| Resource::AllocationFailed { requested })?;
    datagram.extend_from_slice(header);
    for part in payload {
        datagram.extend_from_slice(part);
    }
    datagram
        .get_mut(2..4)
        .ok_or(Malformed::OffsetOverflow)?
        .copy_from_slice(&total_length.to_be_bytes());
    let tos = datagram.get_mut(1).ok_or(Malformed::OffsetOverflow)?;
    *tos = (*tos & 0xfc) | ecn.ipv4_tos_bits();
    let flags = datagram
        .get(6..8)
        .and_then(<[u8]>::first_chunk::<2>)
        .copied()
        .map(u16::from_be_bytes)
        .ok_or(Malformed::OffsetOverflow)?
        & 0xc000;
    datagram
        .get_mut(6..8)
        .ok_or(Malformed::OffsetOverflow)?
        .copy_from_slice(&flags.to_be_bytes());
    datagram
        .get_mut(10..12)
        .ok_or(Malformed::OffsetOverflow)?
        .fill(0);
    let checksum = crate::protocol::checksum(
        datagram
            .get(..header.len())
            .ok_or(Malformed::OffsetOverflow)?,
    );
    datagram
        .get_mut(10..12)
        .ok_or(Malformed::OffsetOverflow)?
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
        .checked_sub(Ipv6Header::LENGTH)
        .ok_or(Malformed::OffsetOverflow)?;
    let payload_bytes = payload_length(payload)?;
    let payload_length = extension_length
        .checked_add(payload_bytes)
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(Malformed::ReconstructedLength {
            family: Family::Ipv6,
        })?;
    let requested = prefix
        .len()
        .checked_add(payload_bytes)
        .ok_or(Malformed::OffsetOverflow)?;
    let mut datagram = Vec::new();
    datagram
        .try_reserve_exact(requested)
        .map_err(|_| Resource::AllocationFailed { requested })?;
    datagram.extend_from_slice(prefix);
    for part in payload {
        datagram.extend_from_slice(part);
    }
    datagram
        .get_mut(4..6)
        .ok_or(Malformed::OffsetOverflow)?
        .copy_from_slice(&payload_length.to_be_bytes());
    let traffic_class = datagram.get_mut(1).ok_or(Malformed::OffsetOverflow)?;
    *traffic_class = (*traffic_class & !0x30) | ecn.ipv6_traffic_class_bits();
    *datagram
        .get_mut(predecessor_next_header_offset)
        .ok_or(Malformed::OffsetOverflow)? = next_header;
    Ok(Bytes::from(datagram))
}
