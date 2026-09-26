// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Retained-header sizing and materialization for admitted fragments, and
//! exact network-header reconstruction after a complete payload is admitted.

use super::validation::{FAMILY_MISMATCH, IPV6_HEADER_LENGTH, Incoming, IncomingReconstruction};
use super::{Bytes, DatagramState, Ecn, Error, Family, Malformed, Reconstruction, Resource};

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
        .ok_or(Malformed::OffsetOverflow.into())
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

pub(super) fn reconstruction_retained_bytes(
    existing: Option<&DatagramState>,
    incoming: &Incoming,
) -> Result<usize, Error> {
    let established = existing.map(|state| &state.reconstruction);
    match &incoming.reconstruction {
        IncomingReconstruction::Ipv4 { header } => match established {
            Some(Reconstruction::Ipv4 {
                first_header: Some(first_header),
                ..
            }) => Ok(first_header.len()),
            Some(Reconstruction::Ipv4 {
                first_header: None, ..
            })
            | None => Ok(if incoming.offset == 0 {
                header.len()
            } else {
                0
            }),
            Some(Reconstruction::Ipv6 { .. }) => Err(FAMILY_MISMATCH),
        },
        IncomingReconstruction::Ipv6 { prefix, .. } => match established {
            // The offset-zero fragment's prefix replaces a provisional one, so
            // admission must account for the prefix the datagram will retain.
            Some(Reconstruction::Ipv6 {
                prefix: _,
                from_offset_zero,
                ..
            }) if !*from_offset_zero && incoming.offset == 0 => Ok(prefix.len()),
            Some(Reconstruction::Ipv6 {
                prefix: established_prefix,
                ..
            }) => Ok(established_prefix.len()),
            None => Ok(prefix.len()),
            Some(Reconstruction::Ipv4 { .. }) => Err(FAMILY_MISMATCH),
        },
    }
}

/// Bytes [`materialize_reconstruction`] newly copies for this fragment while
/// the datagram's current reconstruction is still retained; a retained header
/// or prefix is shared, not copied.
pub(super) fn reconstruction_copied_bytes(
    existing: Option<&DatagramState>,
    incoming: &Incoming,
) -> usize {
    let established = existing.map(|state| &state.reconstruction);
    match (&incoming.reconstruction, established) {
        (
            IncomingReconstruction::Ipv4 { header },
            None
            | Some(Reconstruction::Ipv4 {
                first_header: None, ..
            }),
        ) if incoming.offset == 0 => header.len(),
        (IncomingReconstruction::Ipv6 { prefix, .. }, None) => prefix.len(),
        (
            IncomingReconstruction::Ipv6 { prefix, .. },
            Some(Reconstruction::Ipv6 {
                from_offset_zero: false,
                ..
            }),
        ) if incoming.offset == 0 => prefix.len(),
        _ => 0,
    }
}

pub(super) fn materialize_reconstruction(
    existing: Option<&DatagramState>,
    incoming: &Incoming,
    ecn: Ecn,
) -> Result<Reconstruction, Error> {
    let established = existing.map(|state| &state.reconstruction);
    match &incoming.reconstruction {
        IncomingReconstruction::Ipv4 { header } => {
            let established_first = match established {
                Some(Reconstruction::Ipv4 { first_header, .. }) => first_header.clone(),
                None => None,
                Some(Reconstruction::Ipv6 { .. }) => return Err(FAMILY_MISMATCH),
            };
            Ok(Reconstruction::Ipv4 {
                first_header: match established_first {
                    Some(first_header) => Some(first_header),
                    None if incoming.offset == 0 => Some(copy_bytes(header)?),
                    None => None,
                },
                ecn,
            })
        }
        IncomingReconstruction::Ipv6 {
            prefix,
            predecessor_next_header_offset,
            next_header,
        } => match established {
            Some(Reconstruction::Ipv6 {
                prefix: established_prefix,
                predecessor_next_header_offset: established_predecessor,
                next_header: established_next,
                from_offset_zero,
                ..
            }) => {
                if !from_offset_zero && incoming.offset == 0 {
                    // RFC 8200 §4.5: only the offset-zero fragment's
                    // unfragmentable header and Fragment Next Header are
                    // retained, even when later-offset fragments arrived first.
                    Ok(Reconstruction::Ipv6 {
                        prefix: copy_bytes(prefix)?,
                        predecessor_next_header_offset: *predecessor_next_header_offset,
                        next_header: *next_header,
                        ecn,
                        from_offset_zero: true,
                    })
                } else {
                    Ok(Reconstruction::Ipv6 {
                        prefix: established_prefix.clone(),
                        predecessor_next_header_offset: *established_predecessor,
                        next_header: *established_next,
                        ecn,
                        from_offset_zero: *from_offset_zero,
                    })
                }
            }
            None => Ok(Reconstruction::Ipv6 {
                prefix: copy_bytes(prefix)?,
                predecessor_next_header_offset: *predecessor_next_header_offset,
                next_header: *next_header,
                ecn,
                from_offset_zero: incoming.offset == 0,
            }),
            Some(Reconstruction::Ipv4 { .. }) => Err(FAMILY_MISMATCH),
        },
    }
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
        .checked_sub(IPV6_HEADER_LENGTH)
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
