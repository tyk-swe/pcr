// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Portable implementation boundary for PacketcraftR's packet kernel.
//!
//! Applications should normally import these APIs through the `packetcraftr`
//! façade, which preserves the documented stable paths.

#![warn(unreachable_pub)]
#![forbid(unsafe_code)]

pub mod core;
pub mod error;

pub use core::*;
pub use error::*;
