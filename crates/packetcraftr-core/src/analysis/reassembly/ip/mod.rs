// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded IPv4 and IPv6 fragment reassembly.
//!
//! This standalone algorithm accepts exact decoded fragment metadata. It does
//! not alter physical frames or single-frame dissection. Complete outcomes are
//! raw network-layer datagrams that a caller may decode as a separate derived
//! view.

use std::collections::HashMap;
use std::time::Instant;

use bytes::Bytes;

use super::Limits;
use super::expiry::ExpiryIndex;

mod contract;
pub use contract::{
    CompletedDatagram, DatagramKey, Error, Family, Fragment, FragmentDisposition, FragmentOutcome,
    IncompleteDatagram, IncompleteReason, Ipv4DatagramKey, Ipv4Fragment, Ipv6DatagramKey,
    Ipv6Fragment, MalformedError, OverlapPolicy, PushOutcome, ResourceError, RetiredDatagrams,
};

mod engine;

// This deliberately coarse reservation covers the hash-table key/state and
// load-factor slack, transient old+new tables during geometric growth, the
// duplicated expiry key and both B-tree node levels, and allocator rounding.
// It is more than eight times the fixed owned-value footprint on supported
// targets; payload, ranges, and reconstruction bytes are charged separately.
const DATAGRAM_METADATA_CHARGE: usize = 4_096;
const RANGE_METADATA_CHARGE: usize = 64;

#[derive(Clone, Debug)]
struct RetainedRange {
    start: usize,
    bytes: Bytes,
}

impl RetainedRange {
    fn end(&self) -> Option<usize> {
        self.start.checked_add(self.bytes.len())
    }
}

#[derive(Clone, Debug)]
enum Reconstruction {
    Ipv4 {
        first_header: Option<Bytes>,
    },
    Ipv6 {
        prefix: Bytes,
        predecessor_next_header_offset: usize,
        next_header: u8,
    },
}

impl Reconstruction {
    fn retained_bytes(&self) -> usize {
        match self {
            Self::Ipv4 { first_header } => first_header.as_ref().map_or(0, Bytes::len),
            Self::Ipv6 { prefix, .. } => prefix.len(),
        }
    }
}

#[derive(Clone, Debug)]
struct DatagramState {
    ranges: Vec<RetainedRange>,
    unique_bytes: usize,
    fragment_count: usize,
    duplicate_fragments: usize,
    overlap_bytes: usize,
    final_length: Option<usize>,
    max_non_final_end: Option<usize>,
    reconstruction: Reconstruction,
    last_update: Instant,
    deadline: Option<Instant>,
}

impl DatagramState {
    fn memory_charge(&self) -> Option<usize> {
        self.ranges
            .len()
            .checked_mul(RANGE_METADATA_CHARGE)
            .and_then(|charge| charge.checked_add(self.unique_bytes))
            .and_then(|charge| charge.checked_add(self.reconstruction.retained_bytes()))
    }
}

/// Stateful, bounded IP fragment reassembler.
#[derive(Debug)]
pub struct Reassembler {
    limits: Limits,
    overlap_policy: OverlapPolicy,
    datagrams: HashMap<DatagramKey, DatagramState>,
    expiry: ExpiryIndex<DatagramKey>,
    aggregate_payload_bytes: usize,
    aggregate_memory_charge: usize,
    charged_datagram_slots: usize,
}

#[cfg(test)]
mod memory_charge_tests {
    use std::collections::BTreeSet;
    use std::mem::size_of;
    use std::time::Instant;

    use super::*;

    #[test]
    fn datagram_metadata_reservation_dominates_fixed_collection_values() {
        let fixed_values = size_of::<DatagramState>()
            .checked_add(size_of::<DatagramKey>().saturating_mul(2))
            .and_then(|charge| charge.checked_add(size_of::<Instant>()))
            .and_then(|charge| charge.checked_add(size_of::<BTreeSet<DatagramKey>>()))
            .expect("fixed metadata sizes fit usize");
        let conservative_floor = fixed_values
            .checked_mul(8)
            .expect("small metadata multiplier fits usize");

        assert!(DATAGRAM_METADATA_CHARGE >= conservative_floor);
    }
}
