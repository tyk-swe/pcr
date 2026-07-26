// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Platform-neutral live-network contracts: interfaces, routing, neighbor
//! discovery, transmission, and capture.
//!
//! Every provider here is a trait or an owned portable value. Operating-system
//! implementations live in `packetcraftr-net-native`, which depends on this
//! crate; nothing in this crate depends on a native backend.

#![forbid(unsafe_code)]

pub mod capture;
mod error;
pub mod exchange;
pub mod interface;
pub mod link;
pub mod neighbor;
pub mod route;
mod stats;
pub mod transmit;

pub use error::Error;
pub use stats::Stats;
