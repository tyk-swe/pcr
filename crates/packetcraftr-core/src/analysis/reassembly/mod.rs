// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Standalone bounded IP/TCP reassembly from [`ip::Fragment`] or
//! [`tcp::Segment`]. Both engines key retained state by capture scope and
//! expose complete resource and idle-expiry bounds through their `Limits`.
//!
//! IP requires an explicit [`ip::OverlapPolicy`] and emits raw datagrams on
//! completion. TCP consumes exact payload, sequence state, and control flags.

pub mod ip;
pub mod tcp;

mod expiry;
