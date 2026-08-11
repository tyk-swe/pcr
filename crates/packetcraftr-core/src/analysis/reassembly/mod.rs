// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded IPv4/IPv6 fragment and TCP stream reassembly algorithms.
//!
//! These are standalone algorithms, not a capture or decode pipeline. Map
//! decoded layers into [`fragment::Fragment`] or [`tcp::Segment`], then push
//! each value into the corresponding reassembler.
//!
//! For TCP, [`tcp::FlowKey`] carries the IP endpoints and transport ports;
//! [`tcp::Segment`] adds the sequence number, exact payload bytes, and control
//! flags. For fragments, [`fragment::DatagramKey`] carries the IP endpoints,
//! identification, and next-header value; [`fragment::Fragment`] adds the byte
//! offset, more-fragments flag, and payload. Convert IPv4's eight-byte offset
//! units to bytes. IPv6 supplies the equivalent values from its fragment
//! extension header.

pub mod fragment;
pub mod tcp;

mod limits;
pub use limits::Limits;
