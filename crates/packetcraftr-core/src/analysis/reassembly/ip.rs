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
