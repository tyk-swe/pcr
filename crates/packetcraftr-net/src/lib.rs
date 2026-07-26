// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Live network interfaces, routing, neighbor discovery, transmission, and capture.
//!
//! Native handles and platform-specific representations remain behind the private
//! `platform` boundary. Public contracts are grouped by responsibility and use
//! concise names within their owning namespace.

pub mod capture;
mod error;
pub mod exchange;
pub mod interface;
pub mod link;
pub mod neighbor;
mod platform;
pub mod route;
pub mod transmit;

pub use error::Error;
