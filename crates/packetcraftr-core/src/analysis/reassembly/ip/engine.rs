// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BinaryHeap;
use std::net::Ipv4Addr;
use std::time::Instant;

use bytes::Bytes;

use super::{
    CompletedDatagram, DatagramKey, DatagramState, Error, Family, Fragment, FragmentDisposition,
    FragmentOutcome, IncompleteDatagram, IncompleteReason, Limits, MalformedError, OverlapPolicy,
    PushOutcome, Reassembler, Reconstruction, ResourceError, RetainedRange, RetiredDatagrams,
};

const IPV4_MIN_HEADER_LENGTH: usize = 20;
const IPV6_HEADER_LENGTH: usize = 40;
const IPV6_FRAGMENT_HEADER_LENGTH: usize = 8;
const MAX_WIRE_LENGTH: usize = 65_535;
const IPV6_FRAGMENT_DISCRIMINATOR: u8 = 44;

/// Retained state whose family disagrees with the key it was found under.
const FAMILY_MISMATCH: Error = Error::Inconsistent {
    reason: "retained datagram family disagrees with its key",
};
/// A complete IPv4 datagram covers offset zero, so the fragment that filled
/// it recorded the header every reconstruction needs.
const MISSING_OFFSET_ZERO_HEADER: Error = Error::Inconsistent {
    reason: "complete IPv4 payload has no offset-zero header",
};
/// Reconstruction is only ever asked for after completion is established.
const INCOMPLETE_RECONSTRUCTION: Error = Error::Inconsistent {
    reason: "reconstruction requested before the datagram completed",
};

struct Incoming {
    key: DatagramKey,
    offset: usize,
    end: usize,
    more_fragments: bool,
    payload: Bytes,
    reconstruction: IncomingReconstruction,
}

enum IncomingReconstruction {
    Ipv4 {
        header: Bytes,
    },
    Ipv6 {
        prefix: Bytes,
        predecessor_next_header_offset: usize,
        next_header: u8,
    },
}

struct MergePlan {
    first_affected: usize,
    affected_count: usize,
    union_start: usize,
    union_end: usize,
    added_bytes: usize,
    conflicting_bytes: usize,
    result_range_count: usize,
    duplicate: bool,
}

/// How the retained ranges absorb one admitted fragment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UpdateKind {
    /// Every incoming byte is already retained; nothing is stored.
    Unchanged,
    /// The fragment starts exactly where one retained range ends and touches
    /// no other range, so its bytes extend that range in place.
    Append,
    /// The affected ranges and the fragment are rebuilt into one new range.
    Replace,
}

/// The prepared range update: `Replace` carries the merged range, allocated
/// before any retained state changes.
enum RangeUpdate {
    Unchanged,
    Append,
    Replace(RetainedRange),
}

impl Reassembler {
    #[must_use]
    pub fn new(limits: Limits, overlap_policy: OverlapPolicy) -> Self {
        Self {
            limits,
            overlap_policy,
            datagrams: Default::default(),
            expiry: Default::default(),
            aggregate_payload_bytes: 0,
            aggregate_memory_charge: 0,
            charged_datagram_slots: 0,
        }
    }

    /// Admits one physical fragment and returns its classification, attaching
    /// a raw derived datagram when this arrival fills the last gap.
    pub fn push(&mut self, fragment: Fragment, now: Instant) -> Result<PushOutcome, Error> {
        self.push_with_external_charge(fragment, now, 0)
    }

    /// [`Self::push`], additionally charging memory held by the caller while
    /// it feeds a derived fragment cascade back into this reassembler.
    pub(crate) fn push_with_external_charge(
        &mut self,
        fragment: Fragment,
        now: Instant,
        external_charge: usize,
    ) -> Result<PushOutcome, Error> {
        let incoming = validate_fragment(fragment, &self.limits)?;
        let key = incoming.key.clone();
        let existing = self.datagrams.get(&key);
        if existing.is_none() && self.datagrams.len() >= self.limits.max_datagrams {
            return Err(ResourceError::DatagramLimit {
                limit: self.limits.max_datagrams,
            }
            .into());
        }

        let old_fragment_count = existing.map_or(0, |state| state.fragment_count);
        let fragment_count = old_fragment_count
            .checked_add(1)
            .filter(|count| *count <= self.limits.max_fragments_per_datagram)
            .ok_or(ResourceError::FragmentLimit {
                limit: self.limits.max_fragments_per_datagram,
            })?;

        validate_reconstruction_consistency(existing, &incoming)?;
        let final_length = plan_final_length(existing, &incoming)?;
        validate_family_wire_extent(existing, &incoming, final_length)?;
        let empty_ranges = Vec::new();
        let ranges = existing.map_or(empty_ranges.as_slice(), |state| state.ranges.as_slice());
        let merge = plan_merge(ranges, &incoming)?;
        let update_kind = plan_update_kind(ranges, &incoming, &merge)?;
        if merge.conflicting_bytes != 0 && self.overlap_policy == OverlapPolicy::Reject {
            return Err(MalformedError::ConflictingOverlap {
                bytes: merge.conflicting_bytes,
            }
            .into());
        }

        let old_unique_bytes = existing.map_or(0, |state| state.unique_bytes);
        let new_slot_charge =
            if existing.is_none() && self.datagrams.len() >= self.charged_datagram_slots {
                super::DATAGRAM_METADATA_CHARGE
            } else {
                0
            };
        let unique_bytes = old_unique_bytes
            .checked_add(merge.added_bytes)
            .filter(|bytes| *bytes <= self.limits.max_bytes_per_datagram)
            .ok_or(ResourceError::DatagramByteLimit {
                limit: self.limits.max_bytes_per_datagram,
            })?;
        let reconstruction_bytes = reconstruction_retained_bytes(existing, &incoming)?;
        // Only the bytes this fragment newly retains are charged as an
        // allocation; anything the datagram already held is already counted.
        let reconstruction_allocation = reconstruction_bytes
            .saturating_sub(existing.map_or(0, |state| state.reconstruction.retained_bytes()));
        let last_update = existing.map_or(now, |state| state.last_update.max(now));
        let deadline = Some(last_update.checked_add(self.limits.idle_expiry).ok_or(
            ResourceError::IdleExpiryRange {
                expiry: self.limits.idle_expiry,
            },
        )?);
        let duplicate_fragments = existing
            .map_or(0, |state| state.duplicate_fragments)
            .checked_add(usize::from(merge.duplicate))
            .ok_or(ResourceError::AggregateMemoryLimit {
                limit: self.limits.max_aggregate_bytes,
            })?;
        let overlap_bytes = existing
            .map_or(0, |state| state.overlap_bytes)
            .checked_add(merge.conflicting_bytes)
            .ok_or(ResourceError::AggregateMemoryLimit {
                limit: self.limits.max_aggregate_bytes,
            })?;

        let prospective_charge = merge
            .result_range_count
            .checked_mul(super::RANGE_METADATA_CHARGE)
            .and_then(|charge| charge.checked_add(unique_bytes))
            .and_then(|charge| charge.checked_add(reconstruction_bytes))
            .ok_or(ResourceError::AggregateMemoryLimit {
                limit: self.limits.max_aggregate_bytes,
            })?;
        let old_charge = existing.and_then(DatagramState::memory_charge).unwrap_or(0);
        let aggregate_memory_charge = self
            .aggregate_memory_charge
            .checked_sub(old_charge)
            .and_then(|charge| charge.checked_add(prospective_charge))
            .and_then(|charge| charge.checked_add(new_slot_charge))
            .filter(|charge| {
                charge
                    .checked_add(external_charge)
                    .is_some_and(|total| total <= self.limits.max_aggregate_bytes)
            })
            .ok_or(ResourceError::AggregateMemoryLimit {
                limit: self.limits.max_aggregate_bytes,
            })?;
        // The retained state is not removed until every fallible replacement
        // allocation succeeds, so admission must cover old and new storage at
        // the same time rather than only the eventual steady state.
        let replacement_allocation = replacement_allocation_charge(
            &merge,
            update_kind,
            incoming.payload.len(),
            reconstruction_allocation,
            new_slot_charge,
            self.limits.max_aggregate_bytes,
        )?;
        let replacement_peak_charge = self
            .aggregate_memory_charge
            .checked_add(replacement_allocation)
            .and_then(|charge| charge.checked_add(external_charge))
            .filter(|charge| *charge <= self.limits.max_aggregate_bytes)
            .ok_or(ResourceError::AggregateMemoryLimit {
                limit: self.limits.max_aggregate_bytes,
            })?;
        let aggregate_payload_bytes = self
            .aggregate_payload_bytes
            .checked_sub(old_unique_bytes)
            .and_then(|bytes| bytes.checked_add(unique_bytes))
            .filter(|bytes| *bytes <= self.limits.max_aggregate_bytes)
            .ok_or(ResourceError::AggregateMemoryLimit {
                limit: self.limits.max_aggregate_bytes,
            })?;

        let reconstruction = materialize_reconstruction(existing, &incoming)?;
        let update =
            prepare_range_update(update_kind, ranges, &incoming, &merge, self.overlap_policy)?;
        let max_non_final_end = if incoming.more_fragments {
            Some(
                existing
                    .and_then(|state| state.max_non_final_end)
                    .map_or(incoming.end, |end| end.max(incoming.end)),
            )
        } else {
            existing.and_then(|state| state.max_non_final_end)
        };
        let disposition = if merge.duplicate {
            FragmentDisposition::Duplicate {
                bytes: incoming.payload.len(),
            }
        } else if merge.conflicting_bytes != 0 {
            FragmentDisposition::OverlapResolved {
                policy: self.overlap_policy,
                affected_bytes: merge.conflicting_bytes,
                added_bytes: merge.added_bytes,
            }
        } else {
            FragmentDisposition::Accepted {
                added_bytes: merge.added_bytes,
            }
        };
        let fragment_outcome = FragmentOutcome {
            key: key.clone(),
            disposition,
            fragment_count,
            unique_bytes,
            known_final_length: final_length,
        };
        let previous_deadline = existing.and_then(|state| state.deadline);
        // The datagram is complete when the update leaves exactly one range
        // spanning offset zero to the known final length.
        let completes = final_length.is_some_and(|length| {
            merge.result_range_count == 1 && merge.union_start == 0 && merge.union_end == length
        });
        if completes {
            let final_length = merge.union_end;
            let datagram_charge = reconstructed_length(&reconstruction, final_length)?;
            replacement_peak_charge
                .checked_add(datagram_charge)
                .filter(|charge| *charge <= self.limits.max_aggregate_bytes)
                .ok_or(ResourceError::AggregateMemoryLimit {
                    limit: self.limits.max_aggregate_bytes,
                })?;
            // The completed payload is read from the retained range and the
            // update without storing it, so no retained state changes before
            // the datagram is removed.
            let retained = ranges.first().map(|range| range.bytes.as_slice());
            let payload: [&[u8]; 2] = match &update {
                RangeUpdate::Unchanged => [retained.ok_or(INCOMPLETE_RECONSTRUCTION)?, &[]],
                RangeUpdate::Append => [
                    retained.ok_or(INCOMPLETE_RECONSTRUCTION)?,
                    incoming.payload.as_ref(),
                ],
                RangeUpdate::Replace(range) => [range.bytes.as_slice(), &[]],
            };
            let bytes = reconstruct_bytes(&reconstruction, payload)?;
            let datagram = CompletedDatagram {
                key: key.clone(),
                bytes,
                fragment_count,
                unique_bytes,
                final_payload_length: final_length,
                duplicate_fragments,
                overlap_bytes,
            };
            self.expiry.remove(previous_deadline, &key);
            self.datagrams.remove(&key);
            self.aggregate_payload_bytes = self
                .aggregate_payload_bytes
                .saturating_sub(old_unique_bytes);
            self.aggregate_memory_charge = self.aggregate_memory_charge.saturating_sub(old_charge);
            return Ok(PushOutcome::Completed {
                fragment: fragment_outcome,
                datagram,
            });
        }

        if existing.is_none() {
            self.datagrams
                .try_reserve(1)
                .map_err(|_| ResourceError::AllocationFailed {
                    requested: prospective_charge,
                })?;
        }
        // Applying the update reserves before it writes, so a failure here
        // leaves the retained ranges exactly as they were.
        let new_ranges = match self.datagrams.get_mut(&key) {
            Some(state) => {
                apply_range_update(&mut state.ranges, update, &incoming, &merge)?;
                std::mem::take(&mut state.ranges)
            }
            None => {
                let mut ranges = Vec::new();
                apply_range_update(&mut ranges, update, &incoming, &merge)?;
                ranges
            }
        };
        let new_state = DatagramState {
            ranges: new_ranges,
            unique_bytes,
            fragment_count,
            duplicate_fragments,
            overlap_bytes,
            final_length,
            max_non_final_end,
            reconstruction,
            last_update,
            deadline,
        };
        self.expiry.remove(previous_deadline, &key);
        self.datagrams.insert(key.clone(), new_state);
        self.expiry.insert(deadline, key);
        if new_slot_charge != 0 {
            self.charged_datagram_slots = self.charged_datagram_slots.saturating_add(1);
        }
        self.aggregate_payload_bytes = aggregate_payload_bytes;
        self.aggregate_memory_charge = aggregate_memory_charge;
        Ok(PushOutcome::Accepted(fragment_outcome))
    }

    /// Retires datagrams whose idle deadline is at or before `now`, retaining
    /// at most the configured number of per-datagram outcomes.
    pub fn expire(&mut self, now: Instant) -> RetiredDatagrams {
        let mut retired = RetiredDatagrams::default();
        let retain_limit = self.limits.max_retained_outcomes;
        let datagrams = &mut self.datagrams;
        let aggregate_payload_bytes = &mut self.aggregate_payload_bytes;
        let aggregate_memory_charge = &mut self.aggregate_memory_charge;
        self.expiry.drain_expired(now, |key| {
            let Some(state) = datagrams.remove(&key) else {
                return;
            };
            *aggregate_payload_bytes = aggregate_payload_bytes.saturating_sub(state.unique_bytes);
            *aggregate_memory_charge =
                aggregate_memory_charge.saturating_sub(state.memory_charge().unwrap_or(0));
            retired.push(
                incomplete_datagram(key, state, IncompleteReason::IdleExpired),
                retain_limit,
            );
        });
        retired
    }

    /// Retires every remaining datagram at end of capture, retaining a bounded
    /// stable-key prefix of per-datagram outcomes.
    pub fn flush(&mut self) -> RetiredDatagrams {
        let retain_limit = self.limits.max_retained_outcomes.min(self.datagrams.len());
        let mut smallest = BinaryHeap::with_capacity(retain_limit);
        for key in self.datagrams.keys() {
            if smallest.len() < retain_limit {
                smallest.push(key.clone());
            } else if smallest.peek().is_some_and(|largest| key < largest) {
                smallest.pop();
                smallest.push(key.clone());
            }
        }
        let mut retained_keys = smallest.into_vec();
        retained_keys.sort();

        let mut retired = RetiredDatagrams::default();
        for key in retained_keys {
            let Some(state) = self.datagrams.remove(&key) else {
                continue;
            };
            self.aggregate_payload_bytes = self
                .aggregate_payload_bytes
                .saturating_sub(state.unique_bytes);
            self.aggregate_memory_charge = self
                .aggregate_memory_charge
                .saturating_sub(state.memory_charge().unwrap_or(0));
            retired.outcomes.push(incomplete_datagram(
                key,
                state,
                IncompleteReason::EndOfCapture,
            ));
        }
        for (key, state) in self.datagrams.drain() {
            self.aggregate_payload_bytes = self
                .aggregate_payload_bytes
                .saturating_sub(state.unique_bytes);
            self.aggregate_memory_charge = self
                .aggregate_memory_charge
                .saturating_sub(state.memory_charge().unwrap_or(0));
            retired.omit(key.family());
        }
        self.expiry = Default::default();
        retired
    }

    #[must_use]
    pub fn datagram_count(&self) -> usize {
        self.datagrams.len()
    }

    #[must_use]
    pub const fn aggregate_payload_bytes(&self) -> usize {
        self.aggregate_payload_bytes
    }

    #[must_use]
    pub const fn aggregate_memory_charge(&self) -> usize {
        self.aggregate_memory_charge
    }
}

impl RetiredDatagrams {
    fn push(&mut self, outcome: IncompleteDatagram, limit: usize) {
        if self.outcomes.len() < limit {
            self.outcomes.push(outcome);
        } else {
            self.omit(outcome.family());
        }
    }

    fn omit(&mut self, family: Family) {
        let counter = match family {
            Family::Ipv4 => &mut self.omitted_ipv4,
            Family::Ipv6 => &mut self.omitted_ipv6,
        };
        *counter = counter.saturating_add(1);
    }
}

fn incomplete_datagram(
    key: DatagramKey,
    state: DatagramState,
    reason: IncompleteReason,
) -> IncompleteDatagram {
    IncompleteDatagram {
        key,
        reason,
        fragment_count: state.fragment_count,
        unique_bytes: state.unique_bytes,
        known_final_length: state.final_length,
        duplicate_fragments: state.duplicate_fragments,
        overlap_bytes: state.overlap_bytes,
    }
}

fn validate_fragment(fragment: Fragment, limits: &Limits) -> Result<Incoming, Error> {
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
    let (key, fragment_offset, more_fragments, payload, reconstruction) = match fragment {
        Fragment::Ipv4(fragment) => {
            validate_ipv4_header(&fragment)?;
            (
                DatagramKey::Ipv4(fragment.key),
                fragment.fragment_offset,
                fragment.more_fragments,
                fragment.payload,
                IncomingReconstruction::Ipv4 {
                    header: fragment.header,
                },
            )
        }
        Fragment::Ipv6(fragment) => {
            validate_ipv6_prefix(&fragment)?;
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

fn validate_ipv4_header(fragment: &super::Ipv4Fragment) -> Result<(), Error> {
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
    Ok(())
}

fn validate_ipv6_prefix(fragment: &super::Ipv6Fragment) -> Result<(), Error> {
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
    Ok(())
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

fn validate_reconstruction_consistency(
    existing: Option<&DatagramState>,
    incoming: &Incoming,
) -> Result<(), Error> {
    let Some(existing) = existing else {
        return Ok(());
    };
    match (&existing.reconstruction, &incoming.reconstruction) {
        (Reconstruction::Ipv4 { first_header }, IncomingReconstruction::Ipv4 { header }) => {
            if incoming.offset == 0
                && first_header
                    .as_ref()
                    .is_some_and(|established| !ipv4_headers_match(established, header))
            {
                return Err(MalformedError::InconsistentIpv4Header.into());
            }
        }
        (
            Reconstruction::Ipv6 {
                prefix,
                predecessor_next_header_offset,
                next_header,
            },
            IncomingReconstruction::Ipv6 {
                prefix: incoming_prefix,
                predecessor_next_header_offset: incoming_predecessor,
                next_header: incoming_next_header,
            },
        ) => {
            if next_header != incoming_next_header {
                return Err(MalformedError::InconsistentIpv6NextHeader {
                    expected: *next_header,
                    actual: *incoming_next_header,
                }
                .into());
            }
            if predecessor_next_header_offset != incoming_predecessor
                || !ipv6_prefixes_match(prefix, incoming_prefix)
            {
                return Err(MalformedError::InconsistentIpv6Prefix.into());
            }
        }
        // The datagram key carries the family, so a lookup can never return
        // state of the other one.
        _ => return Err(FAMILY_MISMATCH),
    }
    Ok(())
}

fn ipv4_headers_match(first: &[u8], second: &[u8]) -> bool {
    first.len() == second.len()
        && first.get(..2) == second.get(..2)
        // Total length, fragment offset/MF, and checksum are normalized during
        // reconstruction and legitimately differ per fragment. Reserved/DF
        // are preserved and therefore must agree.
        && first.get(4..6) == second.get(4..6)
        && ipv4_preserved_flags(first) == ipv4_preserved_flags(second)
        && first.get(8..10) == second.get(8..10)
        && first.get(12..) == second.get(12..)
}

fn ipv4_preserved_flags(header: &[u8]) -> Option<u16> {
    header
        .get(6..8)
        .and_then(<[u8]>::first_chunk::<2>)
        .copied()
        .map(u16::from_be_bytes)
        .map(|flags_offset| flags_offset & 0xc000)
}

fn ipv6_prefixes_match(first: &[u8], second: &[u8]) -> bool {
    first.len() == second.len()
        && first.get(..4) == second.get(..4)
        && first.get(6..) == second.get(6..)
}

fn plan_final_length(
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

fn validate_family_wire_extent(
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
                reconstruction: Reconstruction::Ipv4 { first_header },
                ..
            }),
        ) => first_header
            .as_ref()
            .map_or(IPV4_MIN_HEADER_LENGTH, Bytes::len),
        (IncomingReconstruction::Ipv4 { .. }, None) => IPV4_MIN_HEADER_LENGTH,
        (IncomingReconstruction::Ipv6 { prefix, .. }, _) => prefix
            .len()
            .checked_sub(IPV6_HEADER_LENGTH)
            .ok_or(MalformedError::OffsetOverflow)?,
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

fn reconstruction_retained_bytes(
    existing: Option<&DatagramState>,
    incoming: &Incoming,
) -> Result<usize, Error> {
    let established = existing.map(|state| &state.reconstruction);
    match &incoming.reconstruction {
        IncomingReconstruction::Ipv4 { header } => match established {
            Some(Reconstruction::Ipv4 {
                first_header: Some(first_header),
            }) => Ok(first_header.len()),
            Some(Reconstruction::Ipv4 { first_header: None }) | None => {
                Ok(if incoming.offset == 0 {
                    header.len()
                } else {
                    0
                })
            }
            Some(Reconstruction::Ipv6 { .. }) => Err(FAMILY_MISMATCH),
        },
        IncomingReconstruction::Ipv6 { prefix, .. } => match established {
            Some(Reconstruction::Ipv6 {
                prefix: established_prefix,
                ..
            }) => Ok(established_prefix.len()),
            None => Ok(prefix.len()),
            Some(Reconstruction::Ipv4 { .. }) => Err(FAMILY_MISMATCH),
        },
    }
}

fn replacement_allocation_charge(
    merge: &MergePlan,
    update_kind: UpdateKind,
    incoming_bytes: usize,
    reconstruction: usize,
    new_slot_charge: usize,
    limit: usize,
) -> Result<usize, Error> {
    let range_metadata = merge
        .result_range_count
        .checked_mul(super::RANGE_METADATA_CHARGE)
        .ok_or(ResourceError::AggregateMemoryLimit { limit })?;
    let merged_payload = match update_kind {
        UpdateKind::Unchanged => 0,
        UpdateKind::Append => incoming_bytes,
        UpdateKind::Replace => merge
            .union_end
            .checked_sub(merge.union_start)
            .ok_or(MalformedError::OffsetOverflow)?,
    };
    range_metadata
        .checked_add(merged_payload)
        .and_then(|charge| charge.checked_add(reconstruction))
        .and_then(|charge| charge.checked_add(new_slot_charge))
        .ok_or(ResourceError::AggregateMemoryLimit { limit }.into())
}

fn materialize_reconstruction(
    existing: Option<&DatagramState>,
    incoming: &Incoming,
) -> Result<Reconstruction, Error> {
    let established = existing.map(|state| &state.reconstruction);
    match &incoming.reconstruction {
        IncomingReconstruction::Ipv4 { header } => {
            let established_first = match established {
                Some(Reconstruction::Ipv4 { first_header }) => first_header.clone(),
                None => None,
                Some(Reconstruction::Ipv6 { .. }) => return Err(FAMILY_MISMATCH),
            };
            Ok(Reconstruction::Ipv4 {
                first_header: match established_first {
                    Some(first_header) => Some(first_header),
                    None if incoming.offset == 0 => Some(copy_bytes(header)?),
                    None => None,
                },
            })
        }
        IncomingReconstruction::Ipv6 {
            prefix,
            predecessor_next_header_offset,
            next_header,
        } => match established {
            Some(reconstruction @ Reconstruction::Ipv6 { .. }) => Ok(reconstruction.clone()),
            None => Ok(Reconstruction::Ipv6 {
                prefix: copy_bytes(prefix)?,
                predecessor_next_header_offset: *predecessor_next_header_offset,
                next_header: *next_header,
            }),
            Some(Reconstruction::Ipv4 { .. }) => Err(FAMILY_MISMATCH),
        },
    }
}

fn copy_bytes(source: &[u8]) -> Result<Bytes, Error> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(source.len())
        .map_err(|_| ResourceError::AllocationFailed {
            requested: source.len(),
        })?;
    copy.extend_from_slice(source);
    Ok(Bytes::from(copy))
}

fn plan_merge(ranges: &[RetainedRange], incoming: &Incoming) -> Result<MergePlan, Error> {
    let mut first_affected = ranges.len();
    let mut affected_count = 0usize;
    let mut union_start = incoming.offset;
    let mut union_end = incoming.end;
    let mut overlapping_bytes = 0usize;
    let mut conflicting_bytes = 0usize;
    for (index, retained) in ranges.iter().enumerate() {
        let end = retained.end().ok_or(MalformedError::OffsetOverflow)?;
        if end < incoming.offset {
            first_affected = index.checked_add(1).ok_or(MalformedError::OffsetOverflow)?;
            continue;
        }
        if retained.start > incoming.end {
            if affected_count == 0 {
                first_affected = index;
            }
            break;
        }
        if affected_count == 0 {
            first_affected = index;
        }
        affected_count = affected_count
            .checked_add(1)
            .ok_or(MalformedError::OffsetOverflow)?;
        union_start = union_start.min(retained.start);
        union_end = union_end.max(end);
        let overlap_start = retained.start.max(incoming.offset);
        let overlap_end = end.min(incoming.end);
        if overlap_start < overlap_end {
            let length = overlap_end
                .checked_sub(overlap_start)
                .ok_or(MalformedError::OffsetOverflow)?;
            overlapping_bytes = overlapping_bytes
                .checked_add(length)
                .ok_or(MalformedError::OffsetOverflow)?;
            let retained_start = overlap_start
                .checked_sub(retained.start)
                .ok_or(MalformedError::OffsetOverflow)?;
            let incoming_start = overlap_start
                .checked_sub(incoming.offset)
                .ok_or(MalformedError::OffsetOverflow)?;
            let retained_end = retained_start
                .checked_add(length)
                .ok_or(MalformedError::OffsetOverflow)?;
            let incoming_end = incoming_start
                .checked_add(length)
                .ok_or(MalformedError::OffsetOverflow)?;
            let retained_overlap = retained
                .bytes
                .get(retained_start..retained_end)
                .ok_or(MalformedError::OffsetOverflow)?;
            let incoming_overlap = incoming
                .payload
                .get(incoming_start..incoming_end)
                .ok_or(MalformedError::OffsetOverflow)?;
            // A retransmitted fragment overlaps byte-for-byte, so settle that
            // case with one slice compare before counting byte by byte.
            if retained_overlap != incoming_overlap {
                conflicting_bytes = conflicting_bytes
                    .checked_add(
                        retained_overlap
                            .iter()
                            .zip(incoming_overlap)
                            .filter(|(first, second)| first != second)
                            .count(),
                    )
                    .ok_or(MalformedError::OffsetOverflow)?;
            }
        }
    }
    let added_bytes = incoming
        .payload
        .len()
        .checked_sub(overlapping_bytes)
        .ok_or(MalformedError::OffsetOverflow)?;
    let result_range_count = ranges
        .len()
        .checked_add(1)
        .and_then(|count| count.checked_sub(affected_count))
        .ok_or(MalformedError::OffsetOverflow)?;
    Ok(MergePlan {
        first_affected,
        affected_count,
        union_start,
        union_end,
        added_bytes,
        conflicting_bytes,
        result_range_count,
        duplicate: added_bytes == 0 && conflicting_bytes == 0,
    })
}

fn plan_update_kind(
    ranges: &[RetainedRange],
    incoming: &Incoming,
    plan: &MergePlan,
) -> Result<UpdateKind, Error> {
    if plan.duplicate {
        return Ok(UpdateKind::Unchanged);
    }
    if plan.affected_count == 1 && plan.added_bytes == incoming.payload.len() {
        let affected = ranges
            .get(plan.first_affected)
            .ok_or(MalformedError::OffsetOverflow)?;
        if affected.end() == Some(incoming.offset) {
            return Ok(UpdateKind::Append);
        }
    }
    Ok(UpdateKind::Replace)
}

fn prepare_range_update(
    kind: UpdateKind,
    ranges: &[RetainedRange],
    incoming: &Incoming,
    plan: &MergePlan,
    policy: OverlapPolicy,
) -> Result<RangeUpdate, Error> {
    match kind {
        UpdateKind::Unchanged => Ok(RangeUpdate::Unchanged),
        UpdateKind::Append => Ok(RangeUpdate::Append),
        UpdateKind::Replace => Ok(RangeUpdate::Replace(merge_affected(
            ranges, incoming, plan, policy,
        )?)),
    }
}

/// Builds the single range covering the fragment and every retained range it
/// touches. Nothing retained is modified.
fn merge_affected(
    ranges: &[RetainedRange],
    incoming: &Incoming,
    plan: &MergePlan,
    policy: OverlapPolicy,
) -> Result<RetainedRange, Error> {
    let union_length = plan
        .union_end
        .checked_sub(plan.union_start)
        .ok_or(MalformedError::OffsetOverflow)?;
    let mut merged = Vec::new();
    merged
        .try_reserve_exact(union_length)
        .map_err(|_| ResourceError::AllocationFailed {
            requested: union_length,
        })?;
    merged.resize(union_length, 0);

    let incoming_start = incoming
        .offset
        .checked_sub(plan.union_start)
        .ok_or(MalformedError::OffsetOverflow)?;
    // Overlapping bytes are resolved by write order: whichever side is
    // written last wins the contested region.
    let incoming_last = policy == OverlapPolicy::Last;
    if !incoming_last {
        copy_into(&mut merged, incoming_start, &incoming.payload)?;
    }
    for retained in ranges
        .iter()
        .skip(plan.first_affected)
        .take(plan.affected_count)
    {
        let relative = retained
            .start
            .checked_sub(plan.union_start)
            .ok_or(MalformedError::OffsetOverflow)?;
        copy_into(&mut merged, relative, &retained.bytes)?;
    }
    if incoming_last {
        copy_into(&mut merged, incoming_start, &incoming.payload)?;
    }
    Ok(RetainedRange {
        start: plan.union_start,
        bytes: merged,
    })
}

/// Stores the prepared update in `ranges`. Every reservation precedes every
/// write, so an error leaves `ranges` untouched.
fn apply_range_update(
    ranges: &mut Vec<RetainedRange>,
    update: RangeUpdate,
    incoming: &Incoming,
    plan: &MergePlan,
) -> Result<(), Error> {
    match update {
        RangeUpdate::Unchanged => Ok(()),
        RangeUpdate::Append => {
            let range = ranges
                .get_mut(plan.first_affected)
                .ok_or(MalformedError::OffsetOverflow)?;
            range
                .bytes
                .try_reserve_exact(incoming.payload.len())
                .map_err(|_| ResourceError::AllocationFailed {
                    requested: incoming.payload.len(),
                })?;
            range.bytes.extend_from_slice(&incoming.payload);
            Ok(())
        }
        RangeUpdate::Replace(merged) => {
            let replaced_end = plan
                .first_affected
                .checked_add(plan.affected_count)
                .ok_or(MalformedError::OffsetOverflow)?;
            if ranges.get(plan.first_affected..replaced_end).is_none() {
                return Err(MalformedError::OffsetOverflow.into());
            }
            if plan.affected_count == 0 {
                ranges
                    .try_reserve(1)
                    .map_err(|_| ResourceError::AllocationFailed {
                        requested: super::RANGE_METADATA_CHARGE,
                    })?;
            }
            // The range slot is reserved above, so the splice cannot allocate.
            ranges.splice(plan.first_affected..replaced_end, std::iter::once(merged));
            Ok(())
        }
    }
}

fn copy_into(target: &mut [u8], start: usize, bytes: &[u8]) -> Result<(), Error> {
    let end = start
        .checked_add(bytes.len())
        .ok_or(MalformedError::OffsetOverflow)?;
    target
        .get_mut(start..end)
        .ok_or(MalformedError::OffsetOverflow)?
        .copy_from_slice(bytes);
    Ok(())
}

/// Wire length of the datagram a complete payload of `payload_length` bytes
/// reconstructs to, including the retained header or prefix.
fn reconstructed_length(
    reconstruction: &Reconstruction,
    payload_length: usize,
) -> Result<usize, Error> {
    let prefix = match reconstruction {
        Reconstruction::Ipv4 { first_header } => first_header
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
fn reconstruct_bytes(reconstruction: &Reconstruction, payload: [&[u8]; 2]) -> Result<Bytes, Error> {
    match reconstruction {
        Reconstruction::Ipv4 { first_header } => reconstruct_ipv4(first_header.as_ref(), payload),
        Reconstruction::Ipv6 {
            prefix,
            predecessor_next_header_offset,
            next_header,
        } => reconstruct_ipv6(
            prefix,
            *predecessor_next_header_offset,
            *next_header,
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

fn reconstruct_ipv4(first_header: Option<&Bytes>, payload: [&[u8]; 2]) -> Result<Bytes, Error> {
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
    *datagram
        .get_mut(predecessor_next_header_offset)
        .ok_or(MalformedError::OffsetOverflow)? = next_header;
    Ok(Bytes::from(datagram))
}
