// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::time::Instant;

use bytes::Bytes;

use super::expiry::ExpiryIndex;

mod model;
pub use model::{
    CompletedDatagram, DatagramKey, Error, Family, Fragment, FragmentDisposition, FragmentOutcome,
    IncompleteDatagram, IncompleteReason, Ipv4DatagramKey, Ipv4Fragment, Ipv6DatagramKey,
    Ipv6Fragment, Malformed, OverlapPolicy, PushOutcome, Resource, RetiredDatagrams,
};

mod engine;
mod limits;
pub(crate) use limits::Field;
pub use limits::Limits;

// Deliberately coarse; payload, ranges, and reconstruction bytes are charged separately.
const DATAGRAM_METADATA_CHARGE: usize = 4_096;
const RANGE_METADATA_CHARGE: usize = 64;

#[derive(Clone, Debug)]
struct RetainedRange {
    start: usize,
    bytes: Vec<u8>,
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
        ecn: Ecn,
    },
    Ipv6 {
        prefix: Bytes,
        predecessor_next_header_offset: usize,
        next_header: u8,
        ecn: Ecn,
        /// Whether `prefix` came from the offset-zero fragment (RFC 8200 §4.5).
        from_offset_zero: bool,
    },
}

impl Reconstruction {
    fn ecn(&self) -> Ecn {
        match self {
            Self::Ipv4 { ecn, .. } | Self::Ipv6 { ecn, .. } => *ecn,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ecn {
    NotEct,
    Ect1,
    Ect0,
    Ce,
}

impl Ecn {
    const fn from_ipv4_tos(tos: u8) -> Self {
        Self::from_bits(tos & 0x03)
    }

    const fn from_ipv6_traffic_class(traffic_class: u8) -> Self {
        // ECN is the Traffic Class's two low bits, here the high nibble of header byte one.
        Self::from_bits((traffic_class & 0x30) >> 4)
    }

    const fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            0 => Self::NotEct,
            1 => Self::Ect1,
            2 => Self::Ect0,
            _ => Self::Ce,
        }
    }

    const fn ipv4_tos_bits(self) -> u8 {
        match self {
            Self::NotEct => 0,
            Self::Ect1 => 1,
            Self::Ect0 => 2,
            Self::Ce => 3,
        }
    }

    const fn ipv6_traffic_class_bits(self) -> u8 {
        self.ipv4_tos_bits() << 4
    }

    /// RFC 3168 §5.3; unspecified mixtures resolve to the lower marking (Not-ECT, else ECT(0)).
    fn merge(self, incoming: Self) -> Result<Self, Malformed> {
        if self == incoming {
            return Ok(self);
        }
        match (self, incoming) {
            (Self::Ce, Self::NotEct) | (Self::NotEct, Self::Ce) => Err(Malformed::InconsistentEcn),
            (Self::Ce, _) | (_, Self::Ce) => Ok(Self::Ce),
            (Self::NotEct, _) | (_, Self::NotEct) => Ok(Self::NotEct),
            _ => Ok(Self::Ect0),
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
    memory_charge: usize,
}

#[derive(Debug, Default)]
struct Retained {
    payload_bytes: usize,
    memory_charge: usize,
    datagram_slots: usize,
}

impl Retained {
    fn release(&mut self, state: &DatagramState) {
        self.payload_bytes = self
            .payload_bytes
            .checked_sub(state.unique_bytes)
            .expect("retained datagram payload was charged on admission");
        self.memory_charge = self
            .memory_charge
            .checked_sub(state.memory_charge)
            .expect("retained datagram storage was charged on admission");
    }
}

#[derive(Debug)]
pub struct Reassembler {
    limits: Limits,
    overlap_policy: OverlapPolicy,
    datagrams: HashMap<DatagramKey, DatagramState>,
    expiry: ExpiryIndex<DatagramKey>,
    retained: Retained,
}

#[cfg(test)]
mod tests {
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

    fn ipv6_fragment(offset: u16, payload: &'static [u8]) -> Fragment {
        let key = Ipv6DatagramKey {
            scope: crate::analysis::scope::Interner::new()
                .intern(None, Vec::new())
                .expect("one empty scope fits"),
            source: "2001:db8::1".parse().expect("fixture source"),
            destination: "2001:db8::2".parse().expect("fixture destination"),
            identification: 7,
        };
        let payload_length = u16::try_from(8 + payload.len()).expect("fixture length fits");
        let mut prefix = vec![0_u8; 40];
        prefix[0] = 0x60;
        prefix[4..6].copy_from_slice(&payload_length.to_be_bytes());
        prefix[6] = 44;
        prefix[7] = 64;
        prefix[8..24].copy_from_slice(&key.source.octets());
        prefix[24..40].copy_from_slice(&key.destination.octets());
        Fragment::Ipv6(Ipv6Fragment {
            key,
            fragment_offset: offset,
            more_fragments: true,
            next_header: 17,
            unfragmentable_prefix: Bytes::from(prefix),
            predecessor_next_header_offset: 6,
            payload: Bytes::from_static(payload),
        })
    }

    #[test]
    fn replacing_a_provisional_ipv6_prefix_charges_its_copy_at_peak() {
        let now = Instant::now();
        let later = ipv6_fragment(1, b"ijklmnop");
        let first = ipv6_fragment(0, b"abcdefgh");
        let mut roomy = Reassembler::new(Limits::default(), OverlapPolicy::Reject).unwrap();
        roomy.push(later.clone(), now).expect("later fragment fits");
        let peak = roomy.aggregate_memory_charge() + RANGE_METADATA_CHARGE + 16 + 40;

        for (limit, admitted) in [(peak - 1, false), (peak, true)] {
            let mut reassembler = Reassembler::new(
                Limits {
                    max_aggregate_bytes: limit,
                    ..Limits::default()
                },
                OverlapPolicy::Reject,
            )
            .unwrap();
            reassembler
                .push(later.clone(), now)
                .expect("later fragment fits");
            let retained = reassembler.aggregate_memory_charge();
            let result = reassembler.push(first.clone(), now);
            if admitted {
                assert!(result.is_ok(), "limit {limit}: {result:?}");
            } else {
                assert_eq!(
                    result,
                    Err(Error::Resource(Resource::AggregateMemoryLimit { limit }))
                );
                assert_eq!(reassembler.aggregate_memory_charge(), retained);
            }
        }
    }
}
