// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Bounded IPv4/IPv6 fragment and TCP stream reassembly algorithms.
//!
//! This is a standalone algorithmic API, not an automatic capture or decode
//! pipeline. Applications capture and decode packets separately, map decoded
//! layers into [`fragment::Fragment`] or [`tcp::Segment`], and push those values
//! into the corresponding reassembler.
//!
//! For example, an application can adapt the built-in decoded layers as follows:
//!
//! ```
//! use packetcraftr::{
//!     packet::{layer::Raw, Packet},
//!     protocol::{network::Ipv4, transport::Tcp},
//!     session::{
//!         fragment::{DatagramKey, Fragment},
//!         tcp::{FlowKey, Segment},
//!     },
//! };
//!
//! fn tcp_segment(packet: &Packet) -> Option<Segment> {
//!     let ipv4 = packet.get::<Ipv4>()?;
//!     let tcp = packet.get::<Tcp>()?;
//!     let payload = packet.get::<Raw>()?;
//!
//!     Some(Segment {
//!         flow: FlowKey {
//!             source: ipv4.source.into(),
//!             source_port: tcp.source_port,
//!             destination: ipv4.destination.into(),
//!             destination_port: tcp.destination_port,
//!         },
//!         sequence: tcp.sequence,
//!         payload: payload.bytes.clone(),
//!         syn: tcp.flags & Tcp::SYN != 0,
//!         fin: tcp.flags & Tcp::FIN != 0,
//!         rst: tcp.flags & Tcp::RST != 0,
//!     })
//! }
//!
//! fn ipv4_fragment(packet: &Packet) -> Option<Fragment> {
//!     let ipv4 = packet.get::<Ipv4>()?;
//!     let payload = packet.get::<Raw>()?;
//!
//!     Some(Fragment {
//!         key: DatagramKey {
//!             source: ipv4.source.into(),
//!             destination: ipv4.destination.into(),
//!             identification: u32::from(ipv4.identification),
//!             next_header: ipv4.protocol.exact().copied()?,
//!         },
//!         // IPv4 stores the fragment offset in eight-byte units.
//!         offset: u32::from(ipv4.fragment_offset) * 8,
//!         more_fragments: ipv4.more_fragments,
//!         bytes: payload.bytes.clone(),
//!     })
//! }
//! ```
//!
//! A decoded, unfragmented TCP packet supplies `Ipv4 + Tcp + Raw` to the first
//! adapter. A decoded IPv4 fragment supplies `Ipv4 + Raw` to the second: its
//! source/destination route, identification, protocol, offset, and more-fragments
//! flag populate the fragment key and range. IPv6 applications perform the same
//! explicit mapping from the IPv6 and fragment-extension layers.

pub mod fragment;
pub mod tcp;

use std::time::Duration;

const DEFAULT_MAX_REASSEMBLY_FLOWS: usize = 8_192;
const DEFAULT_MAX_REASSEMBLY_BYTES_PER_FLOW: usize = 1024 * 1024;
const DEFAULT_MAX_REASSEMBLY_BYTES: usize = 256 * 1024 * 1024;
const DEFAULT_MAX_FRAGMENTS_PER_DATAGRAM: usize = 256;
const DEFAULT_MAX_TCP_SEGMENTS_PER_FLOW: usize = 4_096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReassemblyLimits {
    pub max_flows: usize,
    pub max_bytes_per_flow: usize,
    pub max_aggregate_bytes: usize,
    pub max_fragments_per_datagram: usize,
    pub max_tcp_segments_per_flow: usize,
    pub fragment_expiry: Duration,
    pub tcp_idle_expiry: Duration,
}

impl Default for ReassemblyLimits {
    fn default() -> Self {
        Self {
            max_flows: DEFAULT_MAX_REASSEMBLY_FLOWS,
            max_bytes_per_flow: DEFAULT_MAX_REASSEMBLY_BYTES_PER_FLOW,
            max_aggregate_bytes: DEFAULT_MAX_REASSEMBLY_BYTES,
            max_fragments_per_datagram: DEFAULT_MAX_FRAGMENTS_PER_DATAGRAM,
            max_tcp_segments_per_flow: DEFAULT_MAX_TCP_SEGMENTS_PER_FLOW,
            fragment_expiry: Duration::from_secs(30),
            tcp_idle_expiry: Duration::from_secs(120),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn preferred_public_reassembly_names_are_usable() {
        let limits = super::ReassemblyLimits::default();
        let reassembler =
            super::fragment::Reassembler::new(limits, super::fragment::OverlapPolicy::default());
        assert_eq!(reassembler.flow_count(), 0);
    }
}
