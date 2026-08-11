// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded IPv4/IPv6 fragment and TCP stream reassembly algorithms.
//!
//! This is a standalone algorithmic API, not an automatic capture or decode
//! pipeline. Applications capture and decode packets separately, map decoded
//! layers into [`fragment::Fragment`] or [`tcp::Segment`], and push those values
//! into the corresponding reassembler.
//!
//! For example, an application can adapt the built-in decoded layers as follows:
//!
//! ```text
//! use crate::{layer::Raw, Packet};
//! use crate::protocol::{network::Ipv4, transport::Tcp};
//! use crate::analysis::reassembly::{
//!     fragment::{DatagramKey, Fragment},
//!     tcp::{FlowKey, Segment},
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

mod limits;
pub use limits::Limits;
