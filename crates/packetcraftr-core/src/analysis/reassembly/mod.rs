// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded TCP stream reassembly.
//!
//! This is a standalone algorithm, not a capture or decode pipeline. Map
//! decoded layers into [`tcp::Segment`], then push each value into the
//! reassembler.
//!
//! [`tcp::ScopedFlowKey`] qualifies the endpoint tuple with an exact capture
//! scope; [`tcp::Segment`] adds sequence state, exact payload bytes, and
//! control flags.

pub mod tcp;

mod expiry;
mod limits;
pub use limits::Limits;
