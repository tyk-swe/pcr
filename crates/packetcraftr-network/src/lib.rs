// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Live network interfaces, routing, neighbor discovery, transmission, and capture.

pub mod capture;
mod checksum;
mod error;
mod exchange;
pub mod interface;
pub mod link;
pub mod neighbor;
mod platform;
pub mod route;
pub mod transmit;

pub use error::Error;
