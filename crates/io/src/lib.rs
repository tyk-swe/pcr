// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture, routing, and native-adapter implementation boundary for PacketcraftR.
//!
//! Applications should normally import these APIs through the `packetcraftr`
//! façade, which preserves the documented stable paths.

#![warn(unreachable_pub)]
#![deny(unsafe_code)]

pub use packetcraftr_core::{core, error};
pub use packetcraftr_protocols::protocols;

pub mod io;

pub use io::*;
