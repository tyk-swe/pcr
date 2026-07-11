// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Built-in protocol implementation boundary for PacketcraftR.
//!
//! Applications should normally import these APIs through the `packetcraftr`
//! façade, which preserves the documented stable paths.

#![warn(unreachable_pub)]
#![forbid(unsafe_code)]

pub use packetcraftr_core::core;

pub mod protocols;

pub use protocols::*;
