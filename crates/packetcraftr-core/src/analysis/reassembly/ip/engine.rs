// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BinaryHeap;
use std::net::Ipv4Addr;
use std::time::Instant;

use bytes::Bytes;

use super::{
    CompletedDatagram, DatagramKey, DatagramState, Ecn, Error, Family, Fragment,
    FragmentDisposition, FragmentOutcome, IncompleteDatagram, IncompleteReason, Limits,
    MalformedError, OverlapPolicy, PushOutcome, Reassembler, Reconstruction, ResourceError,
    Retained, RetainedRange, RetiredDatagrams,
};

mod merge;
mod reconstruction;
mod validation;
use merge::{MergePlan, RangeUpdate, UpdateKind, apply_range_update, merge_affected, plan_merge};
use reconstruction::{
    materialize_reconstruction, reconstruct_bytes, reconstructed_length,
    reconstruction_copied_bytes, reconstruction_retained_bytes,
};
use validation::{
    Incoming, accumulated_ecn, plan_final_length, validate_family_wire_extent, validate_fragment,
    validate_reconstruction_consistency,
};

/// Reconstruction is only ever asked for after completion is established.
const INCOMPLETE_RECONSTRUCTION: Error = Error::Inconsistent {
    reason: "reconstruction requested before the datagram completed",
};

/// Validated memory admission for one fragment arrival. Every fallible
/// replacement allocation is bounded by this plan. Allocation and completion
/// peak checks still run before the retained state can change.
struct Charges {
    unique_bytes: usize,
    duplicate_fragments: usize,
    overlap_bytes: usize,
    new_slot_charge: usize,
    prospective_charge: usize,
    aggregate_memory_charge: usize,
    replacement_peak_charge: usize,
    aggregate_payload_bytes: usize,
    last_update: Instant,
    deadline: Option<Instant>,
}

impl Reassembler {
    pub(crate) fn contains_datagram(&self, key: &DatagramKey) -> bool {
        self.datagrams.contains_key(key)
    }
    fn aggregate_limit(&self) -> Error {
        ResourceError::AggregateMemoryLimit {
            limit: self.limits.max_aggregate_bytes,
        }
        .into()
    }

    fn replacement_allocation_charge(
        &self,
        merge: &MergePlan,
        incoming_bytes: usize,
        reconstruction: usize,
        new_slot_charge: usize,
    ) -> Result<usize, Error> {
        let range_metadata = merge
            .result_range_count
            .checked_mul(super::RANGE_METADATA_CHARGE)
            .ok_or_else(|| self.aggregate_limit())?;
        let merged_payload = match merge.kind {
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
            .ok_or_else(|| self.aggregate_limit())
    }

    fn admit_charges(
        &self,
        existing: Option<&DatagramState>,
        incoming: &Incoming,
        merge: &MergePlan,
        now: Instant,
        external_charge: usize,
    ) -> Result<Charges, Error> {
        let old_unique_bytes = existing.map_or(0, |state| state.unique_bytes);
        let new_slot_charge =
            if existing.is_none() && self.datagrams.len() >= self.retained.datagram_slots {
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
        let reconstruction_bytes = reconstruction_retained_bytes(existing, incoming)?;
        // Only the bytes this fragment newly copies are charged as an
        // allocation; a shared header or prefix is already counted, while a
        // replaced provisional IPv6 prefix stays retained beside its copy.
        let reconstruction_allocation = reconstruction_copied_bytes(existing, incoming);
        let last_update = existing.map_or(now, |state| state.last_update.max(now));
        let deadline = Some(last_update.checked_add(self.limits.idle_expiry).ok_or(
            ResourceError::IdleExpiryRange {
                expiry: self.limits.idle_expiry,
            },
        )?);
        let duplicate_fragments = existing
            .map_or(0, |state| state.duplicate_fragments)
            .checked_add(usize::from(merge.kind == UpdateKind::Unchanged))
            .ok_or_else(|| self.aggregate_limit())?;
        let overlap_bytes = existing
            .map_or(0, |state| state.overlap_bytes)
            .checked_add(merge.conflicting_bytes)
            .ok_or_else(|| self.aggregate_limit())?;
        let prospective_charge = merge
            .result_range_count
            .checked_mul(super::RANGE_METADATA_CHARGE)
            .and_then(|charge| charge.checked_add(unique_bytes))
            .and_then(|charge| charge.checked_add(reconstruction_bytes))
            .ok_or_else(|| self.aggregate_limit())?;
        let old_charge = existing.map_or(0, |state| state.memory_charge);
        let aggregate_memory_charge = self
            .retained
            .memory_charge
            .checked_sub(old_charge)
            .and_then(|charge| charge.checked_add(prospective_charge))
            .and_then(|charge| charge.checked_add(new_slot_charge))
            .filter(|charge| {
                charge
                    .checked_add(external_charge)
                    .is_some_and(|total| total <= self.limits.max_aggregate_bytes)
            })
            .ok_or_else(|| self.aggregate_limit())?;
        // The retained state is not removed until every fallible replacement
        // allocation succeeds, so admission must cover old and new storage at
        // the same time rather than only the eventual steady state.
        let replacement_allocation = self.replacement_allocation_charge(
            merge,
            incoming.payload.len(),
            reconstruction_allocation,
            new_slot_charge,
        )?;
        let replacement_peak_charge = self
            .retained
            .memory_charge
            .checked_add(replacement_allocation)
            .and_then(|charge| charge.checked_add(external_charge))
            .filter(|charge| *charge <= self.limits.max_aggregate_bytes)
            .ok_or_else(|| self.aggregate_limit())?;
        let aggregate_payload_bytes = self
            .retained
            .payload_bytes
            .checked_sub(old_unique_bytes)
            .and_then(|bytes| bytes.checked_add(unique_bytes))
            .filter(|bytes| *bytes <= self.limits.max_aggregate_bytes)
            .ok_or_else(|| self.aggregate_limit())?;
        Ok(Charges {
            unique_bytes,
            duplicate_fragments,
            overlap_bytes,
            new_slot_charge,
            prospective_charge,
            aggregate_memory_charge,
            replacement_peak_charge,
            aggregate_payload_bytes,
            last_update,
            deadline,
        })
    }

    #[must_use]
    pub fn new(limits: Limits, overlap_policy: OverlapPolicy) -> Self {
        Self {
            limits,
            overlap_policy,
            datagrams: Default::default(),
            expiry: Default::default(),
            retained: Retained::default(),
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
        let ecn = accumulated_ecn(existing, &incoming)?;
        let final_length = plan_final_length(existing, &incoming)?;
        validate_family_wire_extent(existing, &incoming, final_length)?;
        let empty_ranges = Vec::new();
        let ranges = existing.map_or(empty_ranges.as_slice(), |state| state.ranges.as_slice());
        let merge = plan_merge(ranges, &incoming)?;
        if merge.conflicting_bytes != 0 && self.overlap_policy == OverlapPolicy::Reject {
            return Err(MalformedError::ConflictingOverlap {
                bytes: merge.conflicting_bytes,
            }
            .into());
        }

        let Charges {
            unique_bytes,
            duplicate_fragments,
            overlap_bytes,
            new_slot_charge,
            prospective_charge,
            aggregate_memory_charge,
            replacement_peak_charge,
            aggregate_payload_bytes,
            last_update,
            deadline,
        } = self.admit_charges(existing, &incoming, &merge, now, external_charge)?;

        let reconstruction = materialize_reconstruction(existing, &incoming, ecn)?;
        let update = match merge.kind {
            UpdateKind::Unchanged => RangeUpdate::Unchanged,
            UpdateKind::Append => RangeUpdate::Append,
            UpdateKind::Replace => RangeUpdate::Replace(merge_affected(
                ranges,
                &incoming,
                &merge,
                self.overlap_policy,
            )?),
        };
        let max_non_final_end = if incoming.more_fragments {
            Some(
                existing
                    .and_then(|state| state.max_non_final_end)
                    .map_or(incoming.end, |end| end.max(incoming.end)),
            )
        } else {
            existing.and_then(|state| state.max_non_final_end)
        };
        let disposition = if merge.kind == UpdateKind::Unchanged {
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
                .ok_or_else(|| self.aggregate_limit())?;
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
            if let Some(state) = self.datagrams.remove(&key) {
                self.retained.release(&state);
            }
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
        let mut fresh_ranges = Vec::new();
        let mut slot = self.datagrams.get_mut(&key);
        let ranges = match slot.as_deref_mut() {
            Some(state) => &mut state.ranges,
            None => &mut fresh_ranges,
        };
        apply_range_update(ranges, update, &incoming, &merge)?;
        let new_state = DatagramState {
            ranges: std::mem::take(ranges),
            unique_bytes,
            fragment_count,
            duplicate_fragments,
            overlap_bytes,
            final_length,
            max_non_final_end,
            reconstruction,
            last_update,
            deadline,
            memory_charge: prospective_charge,
        };
        match slot {
            Some(state) => *state = new_state,
            None => {
                self.datagrams.insert(key.clone(), new_state);
            }
        }
        self.expiry.remove(previous_deadline, &key);
        self.expiry.insert(deadline, key);
        if new_slot_charge != 0 {
            self.retained.datagram_slots = self.retained.datagram_slots.saturating_add(1);
        }
        self.retained.payload_bytes = aggregate_payload_bytes;
        self.retained.memory_charge = aggregate_memory_charge;
        Ok(PushOutcome::Accepted(fragment_outcome))
    }

    /// Retires datagrams whose idle deadline is at or before `now`, retaining
    /// at most the configured number of per-datagram outcomes.
    pub fn expire(&mut self, now: Instant) -> RetiredDatagrams {
        let mut retired = RetiredDatagrams::default();
        let retain_limit = self.limits.max_retained_outcomes;
        let datagrams = &mut self.datagrams;
        let retained = &mut self.retained;
        self.expiry.drain_expired(now, |key| {
            let Some(state) = datagrams.remove(&key) else {
                return;
            };
            retained.release(&state);
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
            self.retained.release(&state);
            retired.outcomes.push(incomplete_datagram(
                key,
                state,
                IncompleteReason::EndOfCapture,
            ));
        }
        for (key, state) in self.datagrams.drain() {
            self.retained.release(&state);
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
        self.retained.payload_bytes
    }

    #[must_use]
    pub const fn aggregate_memory_charge(&self) -> usize {
        self.retained.memory_charge
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
