// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded IP datagram and TCP stream reassembly.
//!
//! These are standalone algorithms, not capture or decode pipelines. Map
//! decoded layers into [`ip::Fragment`] or [`tcp::Segment`], then push each
//! value into its family-specific reassembler.
//!
//! [`ip::DatagramKey`] and [`tcp::ScopedFlowKey`] qualify retained state with
//! an exact capture scope. IP reassembly additionally requires an explicit
//! [`ip::OverlapPolicy`] and emits raw network-layer bytes only after exact,
//! bounded completion; TCP segments carry sequence state, exact payload bytes,
//! and control flags.
//!
//! Each engine owns its own [`ip::Limits`] and [`tcp::Limits`], so a caller
//! that fills one has named every payload, metadata, concurrency, and
//! idle-expiry bound that engine enforces.

pub mod ip;
pub mod tcp;

mod expiry;
