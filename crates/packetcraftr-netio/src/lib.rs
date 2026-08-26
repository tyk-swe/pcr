// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Network provider contracts and native I/O adapters.
//!
//! All platform-specific and potentially unsafe I/O is contained here. Higher
//! level transmission and diagnostic workflows remain policy-gated in
//! `packetcraftr`.

pub mod capture;
mod error;
mod exchange;
pub mod interface;
pub mod link;
pub mod neighbor;
mod platform;
pub mod route;
pub mod transmit;

pub use error::Error;
