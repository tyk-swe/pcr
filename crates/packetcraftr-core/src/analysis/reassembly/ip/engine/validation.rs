// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Normalization and pure pre-commit validation for one incoming fragment.
//!
//! Fragment normalization, header validation, retained-state consistency,
//! final-length planning, wire-extent checks, and ECN combination are pure:
//! they never mutate retained state, so a rejected fragment leaves every
//! retained datagram exactly as it was.

use super::super::{Ipv4Fragment, Ipv6Fragment};
use super::{
    Bytes, DatagramKey, DatagramState, Ecn, Error, Fragment, Ipv4Addr, Limits, MalformedError,
    Reconstruction, ResourceError, RetainedRange,
};

const IPV4_MIN_HEADER_LENGTH: usize = 20;
pub(super) const IPV6_HEADER_LENGTH: usize = 40;
const IPV6_FRAGMENT_HEADER_LENGTH: usize = 8;
const MAX_WIRE_LENGTH: usize = 65_535;
const IPV6_FRAGMENT_DISCRIMINATOR: u8 = 44;

/// Retained state whose family disagrees with the key it was found under.
pub(super) const FAMILY_MISMATCH: Error = Error::Inconsistent {
    reason: "retained datagram family disagrees with its key",
};

pub(super) struct Incoming {
    pub(super) key: DatagramKey,
    pub(super) offset: usize,
    pub(super) end: usize,
    pub(super) more_fragments: bool,
    pub(super) payload: Bytes,
    pub(super) reconstruction: IncomingReconstruction,
    pub(super) ecn: Ecn,
}

pub(super) enum IncomingReconstruction {
    Ipv4 {
        header: Bytes,
    },
    Ipv6 {
        prefix: Bytes,
        predecessor_next_header_offset: usize,
        next_header: u8,
    },
}

pub(super) fn validate_fragment(fragment: Fragment, limits: &Limits) -> Result<Incoming, Error> {
    let fragment_offset = match &fragment {
        Fragment::Ipv4(fragment) => fragment.fragment_offset,
        Fragment::Ipv6(fragment) => fragment.fragment_offset,
    };
    if fragment_offset > 0x1fff {
        return Err(MalformedError::OffsetOutOfRange {
            offset: fragment_offset,
        }
        .into());
    }
    let (key, fragment_offset, more_fragments, payload, reconstruction, ecn) = match fragment {
        Fragment::Ipv4(fragment) => {
            let ecn = validate_ipv4_header(&fragment)?;
            (
                DatagramKey::Ipv4(fragment.key),
                fragment.fragment_offset,
                fragment.more_fragments,
                fragment.payload,
                IncomingReconstruction::Ipv4 {
                    header: fragment.header,
                },
                ecn,
            )
        }
        Fragment::Ipv6(fragment) => {
            let ecn = validate_ipv6_prefix(&fragment)?;
            (
                DatagramKey::Ipv6(fragment.key),
                fragment.fragment_offset,
                fragment.more_fragments,
                fragment.payload,
                IncomingReconstruction::Ipv6 {
                    prefix: fragment.unfragmentable_prefix,
                    predecessor_next_header_offset: fragment.predecessor_next_header_offset,
                    next_header: fragment.next_header,
                },
                ecn,
            )
        }
    };
    if fragment_offset == 0 && !more_fragments {
        return Err(MalformedError::AtomicFragment.into());
    }
    if payload.is_empty() {
        return Err(MalformedError::EmptyPayload.into());
    }
    if more_fragments && payload.len() % 8 != 0 {
        return Err(MalformedError::UnalignedNonFinal {
            length: payload.len(),
        }
        .into());
    }
    let offset = usize::from(fragment_offset)
        .checked_mul(8)
        .ok_or(MalformedError::OffsetOverflow)?;
    let end = offset
        .checked_add(payload.len())
        .ok_or(MalformedError::OffsetOverflow)?;
    let incoming = Incoming {
        key,
        offset,
        end,
        more_fragments,
        payload,
        reconstruction,
        ecn,
    };
    validate_family_wire_extent(
        None,
        &incoming,
        (!incoming.more_fragments).then_some(incoming.end),
    )?;
    if incoming.end > limits.max_bytes_per_datagram {
        return Err(ResourceError::DatagramByteLimit {
            limit: limits.max_bytes_per_datagram,
        }
        .into());
    }
    Ok(incoming)
}

/// Validates one IPv4 fragment header and reports its congestion marking so
/// reassembly can merge it independently of the retained header bytes.
fn validate_ipv4_header(fragment: &Ipv4Fragment) -> Result<Ecn, Error> {
    let Some(fixed) = fragment.header.first_chunk::<IPV4_MIN_HEADER_LENGTH>() else {
        return Err(MalformedError::InvalidIpv4Header {
            reason: "header is shorter than twenty bytes",
        }
        .into());
    };
    if fixed[0] >> 4 != 4 {
        return Err(MalformedError::InvalidIpv4Header {
            reason: "version is not four",
        }
        .into());
    }
    let header_length = usize::from(fixed[0] & 0x0f)
        .checked_mul(4)
        .ok_or(MalformedError::OffsetOverflow)?;
    if header_length < IPV4_MIN_HEADER_LENGTH || header_length != fragment.header.len() {
        return Err(MalformedError::InvalidIpv4Header {
            reason: "IHL does not match supplied header bytes",
        }
        .into());
    }
    let total_length = usize::from(u16::from_be_bytes([fixed[2], fixed[3]]));
    if header_length.checked_add(fragment.payload.len()) != Some(total_length) {
        return Err(MalformedError::InvalidIpv4Header {
            reason: "total length does not match header and fragment payload",
        }
        .into());
    }
    let flags_offset = u16::from_be_bytes([fixed[6], fixed[7]]);
    if flags_offset & 0x1fff != fragment.fragment_offset
        || (flags_offset & 0x2000 != 0) != fragment.more_fragments
    {
        return Err(MalformedError::InvalidIpv4Header {
            reason: "wire fragmentation fields do not match the adapter metadata",
        }
        .into());
    }
    if u16::from_be_bytes([fixed[4], fixed[5]]) != fragment.key.identification
        || fixed[9] != fragment.key.protocol
        || Ipv4Addr::from([fixed[12], fixed[13], fixed[14], fixed[15]]) != fragment.key.source
        || Ipv4Addr::from([fixed[16], fixed[17], fixed[18], fixed[19]]) != fragment.key.destination
    {
        return Err(MalformedError::InvalidIpv4Header {
            reason: "header identity does not match the datagram key",
        }
        .into());
    }
    Ok(Ecn::from_ipv4_tos(fixed[1]))
}

/// Validates one IPv6 fragment's unfragmentable prefix and reports its
/// congestion marking so reassembly can merge it independently of the retained
/// prefix bytes.
fn validate_ipv6_prefix(fragment: &Ipv6Fragment) -> Result<Ecn, Error> {
    let Some(base) = fragment
        .unfragmentable_prefix
        .first_chunk::<IPV6_HEADER_LENGTH>()
    else {
        return Err(MalformedError::InvalidIpv6Prefix {
            reason: "prefix is shorter than the IPv6 base header",
        }
        .into());
    };
    if base[0] >> 4 != 6 {
        return Err(MalformedError::InvalidIpv6Prefix {
            reason: "version is not six",
        }
        .into());
    }
    if ipv6_fragment_predecessor(&fragment.unfragmentable_prefix)
        != Some(fragment.predecessor_next_header_offset)
    {
        return Err(MalformedError::InvalidIpv6Prefix {
            reason: "predecessor is not the final structurally valid Next Header field",
        }
        .into());
    }
    let prefix_payload_length = fragment
        .unfragmentable_prefix
        .len()
        .checked_sub(IPV6_HEADER_LENGTH)
        .and_then(|length| length.checked_add(IPV6_FRAGMENT_HEADER_LENGTH))
        .and_then(|length| length.checked_add(fragment.payload.len()))
        .ok_or(MalformedError::OffsetOverflow)?;
    let declared = usize::from(u16::from_be_bytes([base[4], base[5]]));
    if prefix_payload_length != declared {
        return Err(MalformedError::InvalidIpv6Prefix {
            reason: "payload length does not match prefix, Fragment header, and payload",
        }
        .into());
    }
    let source = fragment
        .unfragmentable_prefix
        .get(8..)
        .and_then(<[u8]>::first_chunk::<16>)
        .copied()
        .map(std::net::Ipv6Addr::from);
    let destination = fragment
        .unfragmentable_prefix
        .get(24..)
        .and_then(<[u8]>::first_chunk::<16>)
        .copied()
        .map(std::net::Ipv6Addr::from);
    if source != Some(fragment.key.source) || destination != Some(fragment.key.destination) {
        return Err(MalformedError::InvalidIpv6Prefix {
            reason: "base-header identity does not match the datagram key",
        }
        .into());
    }
    Ok(Ecn::from_ipv6_traffic_class(base[1]))
}

fn ipv6_fragment_predecessor(prefix: &[u8]) -> Option<usize> {
    let base = prefix.first_chunk::<IPV6_HEADER_LENGTH>()?;
    let mut next_header = base[6];
    let mut predecessor = 6usize;
    let mut cursor = IPV6_HEADER_LENGTH;
    loop {
        if next_header == IPV6_FRAGMENT_DISCRIMINATOR {
            return (cursor == prefix.len()).then_some(predecessor);
        }
        let header = prefix.get(cursor..)?;
        let length =
            crate::protocol::network::ipv6_extension_header_length(next_header, *header.get(1)?)?;
        let end = cursor.checked_add(length)?;
        if end > prefix.len() {
            return None;
        }
        predecessor = cursor;
        next_header = *header.first()?;
        cursor = end;
    }
}

pub(super) fn validate_reconstruction_consistency(
    existing: Option<&DatagramState>,
    incoming: &Incoming,
) -> Result<(), Error> {
    let Some(existing) = existing else {
        return Ok(());
    };
    match (&existing.reconstruction, &incoming.reconstruction) {
        (Reconstruction::Ipv4 { first_header, .. }, IncomingReconstruction::Ipv4 { header }) => {
            if incoming.offset == 0
                && first_header
                    .as_ref()
                    .is_some_and(|established| !ipv4_headers_match(established, header))
            {
                return Err(MalformedError::InconsistentIpv4Header.into());
            }
        }
        (
            Reconstruction::Ipv6 { .. },
            IncomingReconstruction::Ipv6 {
                prefix: _,
                predecessor_next_header_offset: _,
                next_header: _,
            },
        ) => {
            // RFC 8200 §4.5 allows the number and content of the unfragmentable
            // headers and the Fragment Next Header to differ between fragments.
            // Only the offset-zero fragment's values are retained, which
            // Reconstruction::from_offset_zero tracks for materialization.
        }
        // The datagram key carries the family, so a lookup can never return
        // state of the other one.
        _ => return Err(FAMILY_MISMATCH),
    }
    Ok(())
}

fn ipv4_headers_match(first: &[u8], second: &[u8]) -> bool {
    first.len() == second.len()
        && first.first() == second.first()
        // ECN is merged across fragments per RFC 3168, so it may differ even
        // between offset-zero duplicates; DSCP is preserved and must agree.
        // Total length, fragment offset/MF, and checksum are normalized during
        // reconstruction and legitimately differ per fragment. Reserved/DF
        // are preserved and therefore must agree.
        && ipv4_dscp(first) == ipv4_dscp(second)
        && first.get(4..6) == second.get(4..6)
        && ipv4_preserved_flags(first) == ipv4_preserved_flags(second)
        && first.get(8..10) == second.get(8..10)
        && first.get(12..) == second.get(12..)
}

fn ipv4_dscp(header: &[u8]) -> Option<u8> {
    header.get(1).map(|tos| tos & 0xfc)
}

fn ipv4_preserved_flags(header: &[u8]) -> Option<u16> {
    header
        .get(6..8)
        .and_then(<[u8]>::first_chunk::<2>)
        .copied()
        .map(u16::from_be_bytes)
        .map(|flags_offset| flags_offset & 0xc000)
}

pub(super) fn plan_final_length(
    existing: Option<&DatagramState>,
    incoming: &Incoming,
) -> Result<Option<usize>, Error> {
    let established = existing.and_then(|state| state.final_length);
    let final_length = if incoming.more_fragments {
        established
    } else {
        if let Some(existing) = established
            && existing != incoming.end
        {
            return Err(MalformedError::ConflictingFinalLength {
                existing,
                new: incoming.end,
            }
            .into());
        }
        Some(incoming.end)
    };
    if let Some(final_length) = final_length {
        if existing
            .and_then(|state| state.max_non_final_end)
            .is_some_and(|end| end == final_length)
        {
            return Err(MalformedError::NonFinalAtFinalLength { final_length }.into());
        }
        if incoming.end > final_length
            || existing.is_some_and(|state| {
                state
                    .ranges
                    .last()
                    .and_then(RetainedRange::end)
                    .is_some_and(|end| end > final_length)
            })
        {
            return Err(MalformedError::BeyondFinalLength { final_length }.into());
        }
        if incoming.more_fragments && incoming.end >= final_length {
            return Err(MalformedError::NonFinalAtFinalLength { final_length }.into());
        }
    }
    Ok(final_length)
}

pub(super) fn validate_family_wire_extent(
    existing: Option<&DatagramState>,
    incoming: &Incoming,
    final_length: Option<usize>,
) -> Result<(), Error> {
    let retained_end = existing
        .and_then(|state| state.ranges.last())
        .and_then(RetainedRange::end)
        .unwrap_or(0);
    let extent = final_length.unwrap_or_else(|| incoming.end.max(retained_end));
    let reconstructed_prefix_length = match (&incoming.reconstruction, existing) {
        (IncomingReconstruction::Ipv4 { header }, _) if incoming.offset == 0 => header.len(),
        (
            IncomingReconstruction::Ipv4 { .. },
            Some(DatagramState {
                reconstruction: Reconstruction::Ipv4 { first_header, .. },
                ..
            }),
        ) => first_header
            .as_ref()
            .map_or(IPV4_MIN_HEADER_LENGTH, Bytes::len),
        (IncomingReconstruction::Ipv4 { .. }, None) => IPV4_MIN_HEADER_LENGTH,
        (IncomingReconstruction::Ipv6 { prefix, .. }, existing) => {
            // An offset-zero fragment replaces a provisional non-zero prefix,
            // so the wire check must use the prefix the datagram will retain.
            let retained = match existing {
                Some(DatagramState {
                    reconstruction:
                        Reconstruction::Ipv6 {
                            prefix: _,
                            from_offset_zero,
                            ..
                        },
                    ..
                }) if !from_offset_zero && incoming.offset == 0 => prefix.len(),
                Some(DatagramState {
                    reconstruction: Reconstruction::Ipv6 { prefix, .. },
                    ..
                }) => prefix.len(),
                _ => prefix.len(),
            };
            retained
                .checked_sub(IPV6_HEADER_LENGTH)
                .ok_or(MalformedError::OffsetOverflow)?
        }
        _ => return Err(FAMILY_MISMATCH),
    };
    if reconstructed_prefix_length
        .checked_add(extent)
        .is_none_or(|length| length > MAX_WIRE_LENGTH)
    {
        return Err(MalformedError::ReconstructedLength {
            family: incoming.key.family(),
        }
        .into());
    }
    Ok(())
}

pub(super) fn accumulated_ecn(
    existing: Option<&DatagramState>,
    incoming: &Incoming,
) -> Result<Ecn, Error> {
    existing.map_or(Ok(incoming.ecn), |state| {
        state
            .reconstruction
            .ecn()
            .merge(incoming.ecn)
            .map_err(Error::from)
    })
}
