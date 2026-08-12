// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded IPv4/IPv6 fragment and TCP stream reassembly algorithms.
//!
//! These are standalone algorithms, not a capture or decode pipeline. Map
//! decoded layers into [`fragment::Fragment`] or [`tcp::Segment`], then push
//! each value into the corresponding reassembler.
//!
//! For TCP, [`tcp::ScopedFlowKey`] qualifies the endpoint tuple with an exact
//! capture scope; [`tcp::Segment`] adds sequence state, exact payload bytes,
//! and control flags. [`fragment::ScopedDatagramKey`] does the same for an IP
//! fragment identity. Convert IPv4's eight-byte offset units to bytes. IPv6
//! supplies the equivalent values from its fragment extension header.

pub mod fragment;
pub mod tcp;

mod expiry;
mod limits;
pub use limits::Limits;
