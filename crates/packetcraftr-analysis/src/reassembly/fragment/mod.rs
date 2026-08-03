// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

use bytes::Bytes;

use super::Limits;

#[cfg(test)]
use accounting::{DATAGRAM_STATE_METADATA_CHARGE, FRAGMENT_SEGMENT_METADATA_CHARGE};
use accounting::{FragmentAccountingInput, datagram_memory_charge_parts, plan_accounting};
use commit::commit_fragment;
use plan::{FragmentMergePlan, plan_fragment_merge};

mod accounting;
mod commit;
mod contract;
pub use contract::*;
mod plan;

#[derive(Debug)]
struct DatagramState {
    segments: BTreeMap<u32, Bytes>,
    final_length: Option<u32>,
    fragment_count: usize,
    stored_bytes: usize,
    last_update: Instant,
    had_conflicting_overlap: bool,
}

#[derive(Debug)]
pub struct Reassembler {
    limits: Limits,
    overlap_policy: OverlapPolicy,
    flows: HashMap<DatagramKey, DatagramState>,
    aggregate_bytes: usize,
    aggregate_memory_charge: usize,
}

impl Reassembler {
    pub fn new(limits: Limits, overlap_policy: OverlapPolicy) -> Self {
        Self {
            limits,
            overlap_policy,
            flows: HashMap::new(),
            aggregate_bytes: 0,
            aggregate_memory_charge: 0,
        }
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    pub fn aggregate_bytes(&self) -> usize {
        self.aggregate_bytes
    }

    pub fn aggregate_memory_charge(&self) -> usize {
        self.aggregate_memory_charge
    }

    /// Admits one fragment, returning an event once a datagram completes.
    ///
    /// # Panics
    ///
    /// Panics if a flow validated earlier in the same call has since
    /// disappeared, or if a completed datagram is missing the segment the
    /// merge plan just placed in it. Both would mean this reassembler had
    /// corrupted its own state; every input-driven rejection, including
    /// conflicting overlaps and exhausted budgets, is reported through
    /// [`enum@Error`].
    pub fn push(&mut self, fragment: Fragment, now: Instant) -> Result<Option<Event>, Error> {
        let Fragment {
            key,
            offset,
            more_fragments,
            bytes,
        } = fragment;

        if bytes.is_empty() {
            return Err(Error::EmptyFragment);
        }
        if more_fragments && !bytes.len().is_multiple_of(8) {
            return Err(Error::UnalignedNonFinalFragment {
                length: bytes.len(),
            });
        }
        if !offset.is_multiple_of(8) {
            return Err(Error::UnalignedFragmentOffset { offset });
        }
        let end = offset
            .checked_add(u32::try_from(bytes.len()).map_err(|_| Error::OffsetOverflow)?)
            .ok_or(Error::OffsetOverflow)?;
        if usize::try_from(end).map_or(true, |end| end > self.limits.max_bytes_per_flow) {
            return Err(Error::FlowByteLimit {
                limit: self.limits.max_bytes_per_flow,
            });
        }
        let has_existing_flow = self.flows.contains_key(&key);
        if !has_existing_flow && !more_fragments && offset == 0 {
            if self.limits.max_fragments_per_datagram == 0 {
                return Err(Error::FragmentLimit { limit: 0 });
            }
            return Ok(Some(Event::Complete(Datagram {
                key,
                bytes,
                fragment_count: 1,
                had_conflicting_overlap: false,
            })));
        }
        if !has_existing_flow && self.flows.len() >= self.limits.max_flows {
            return Err(Error::FlowLimit {
                limit: self.limits.max_flows,
            });
        }

        let (
            old_memory_charge,
            previous_stored_bytes,
            previous_fragment_count,
            final_length,
            merge,
        ) = {
            let existing_state = self.flows.get(&key);
            let old_memory_charge = existing_state.and_then(datagram_memory_charge).unwrap_or(0);
            let previous_stored_bytes = existing_state.map_or(0, |state| state.stored_bytes);
            let previous_fragment_count = existing_state.map_or(0, |state| state.fragment_count);
            let existing_final_length = existing_state.and_then(|state| state.final_length);

            if previous_fragment_count >= self.limits.max_fragments_per_datagram {
                return Err(Error::FragmentLimit {
                    limit: self.limits.max_fragments_per_datagram,
                });
            }
            if let Some(final_length) = existing_final_length
                && end > final_length
            {
                return Err(Error::BeyondFinalLength { final_length });
            }
            if !more_fragments {
                match existing_final_length {
                    Some(existing_length) if existing_length != end => {
                        return Err(Error::ConflictingFinalLength {
                            existing_length,
                            new_length: end,
                        });
                    }
                    _ => {
                        let prior_fragment_extends_past_end = existing_state.is_some_and(|state| {
                            state
                                .segments
                                .last_key_value()
                                .is_some_and(|(offset, bytes)| {
                                    u64::from(*offset) + bytes.len() as u64 > u64::from(end)
                                })
                        });
                        if prior_fragment_extends_past_end {
                            return Err(Error::BeyondFinalLength { final_length: end });
                        }
                    }
                }
            }

            let merge = match existing_state {
                Some(state) => {
                    plan_fragment_merge(&state.segments, offset, &bytes, self.overlap_policy)?
                }
                None => FragmentMergePlan::disjoint(bytes.len(), offset, end, 1),
            };
            (
                old_memory_charge,
                previous_stored_bytes,
                previous_fragment_count,
                (!more_fragments).then_some(end).or(existing_final_length),
                merge,
            )
        };

        let accounting = plan_accounting(
            &self.limits,
            FragmentAccountingInput {
                previous_stored_bytes,
                previous_fragment_count,
                added_bytes: merge.added_bytes,
                segment_count: merge.segment_count,
                aggregate_bytes: self.aggregate_bytes,
                old_memory_charge,
                aggregate_memory_charge: self.aggregate_memory_charge,
            },
        )?;
        let stored_bytes = accounting.stored_bytes;
        let aggregate = accounting.aggregate_bytes;
        let new_memory_charge = accounting.new_memory_charge;
        let aggregate_memory_charge = accounting.aggregate_memory_charge;
        let fragment_count = accounting.fragment_count;

        if has_existing_flow {
            let complete = {
                let state = self
                    .flows
                    .get_mut(&key)
                    .expect("validated fragment flow remains present");
                commit_fragment(&mut state.segments, offset, bytes, merge)?;
                state.final_length = final_length;
                state.stored_bytes = stored_bytes;
                state.fragment_count = fragment_count;
                state.last_update = state.last_update.max(now);
                state.had_conflicting_overlap |= merge.has_conflicting_overlap;
                state
                    .final_length
                    .filter(|length| is_complete(&state.segments, *length))
            };

            self.aggregate_bytes = aggregate;
            self.aggregate_memory_charge = aggregate_memory_charge;
            if let Some(length) = complete {
                let state = self
                    .flows
                    .remove(&key)
                    .expect("completed fragment flow remains present");
                self.aggregate_bytes = self.aggregate_bytes.saturating_sub(state.stored_bytes);
                self.aggregate_memory_charge = self
                    .aggregate_memory_charge
                    .saturating_sub(new_memory_charge);
                let (_, datagram_bytes) = state
                    .segments
                    .into_iter()
                    .next()
                    .expect("complete datagram retains its coalesced segment");
                debug_assert_eq!(datagram_bytes.len(), length as usize);
                return Ok(Some(Event::Complete(Datagram {
                    key,
                    bytes: datagram_bytes,
                    fragment_count: state.fragment_count,
                    had_conflicting_overlap: state.had_conflicting_overlap,
                })));
            }
            return Ok(None);
        }

        let mut state = DatagramState {
            segments: BTreeMap::new(),
            final_length,
            fragment_count,
            stored_bytes,
            last_update: now,
            had_conflicting_overlap: merge.has_conflicting_overlap,
        };
        commit_fragment(&mut state.segments, offset, bytes, merge)?;
        self.flows.insert(key, state);
        self.aggregate_bytes = aggregate;
        self.aggregate_memory_charge = aggregate_memory_charge;
        Ok(None)
    }

    pub fn expire(&mut self, now: Instant) -> Vec<Event> {
        let mut expired = self
            .flows
            .iter()
            .filter_map(|(key, state)| {
                now.checked_duration_since(state.last_update)
                    .filter(|idle| *idle >= self.limits.fragment_expiry)
                    .map(|_| key.clone())
            })
            .collect::<Vec<_>>();
        expired.sort_by_key(|key| {
            (
                key.source,
                key.destination,
                key.identification,
                key.next_header,
            )
        });
        expired
            .into_iter()
            .filter_map(|key| {
                let state = self.flows.remove(&key)?;
                self.aggregate_bytes = self.aggregate_bytes.saturating_sub(state.stored_bytes);
                let charge = datagram_memory_charge(&state).unwrap_or(0);
                self.aggregate_memory_charge = self.aggregate_memory_charge.saturating_sub(charge);
                Some(Event::Expired {
                    key,
                    received_bytes: state.stored_bytes,
                    fragment_count: state.fragment_count,
                })
            })
            .collect()
    }

    pub fn flush(&mut self) -> Vec<Event> {
        let mut keys = self.flows.keys().cloned().collect::<Vec<_>>();
        keys.sort_by_key(|key| {
            (
                key.source,
                key.destination,
                key.identification,
                key.next_header,
            )
        });
        let events = keys
            .into_iter()
            .filter_map(|key| {
                let state = self.flows.remove(&key)?;
                Some(Event::Expired {
                    key,
                    received_bytes: state.stored_bytes,
                    fragment_count: state.fragment_count,
                })
            })
            .collect();
        self.aggregate_bytes = 0;
        self.aggregate_memory_charge = 0;
        events
    }
}

fn datagram_memory_charge(state: &DatagramState) -> Option<usize> {
    datagram_memory_charge_parts(state.stored_bytes, state.segments.len())
}

fn is_complete(segments: &BTreeMap<u32, Bytes>, final_length: u32) -> bool {
    let mut cursor = 0u32;
    for (offset, bytes) in segments {
        if *offset != cursor {
            return false;
        }
        let Ok(length) = u32::try_from(bytes.len()) else {
            return false;
        };
        let Some(end) = cursor.checked_add(length) else {
            return false;
        };
        cursor = end;
    }
    cursor == final_length
}

#[cfg(test)]
mod tests;
