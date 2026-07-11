// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded session and reassembly implementation boundary for PacketcraftR.
//!
//! Applications should normally import these APIs through the `packetcraftr`
//! façade, which preserves the documented stable paths.

#![warn(unreachable_pub)]
#![forbid(unsafe_code)]

pub mod session;

pub use session::*;
