// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Network provider contracts and native I/O adapters.
//!
//! All platform-specific and potentially unsafe I/O is contained here. Higher
//! level transmission and diagnostic workflows remain policy-gated in
//! `packetcraftr`.

// This crate is the only one permitted to contain `unsafe`, and the rule is
// declared once, here. Every module inherits the denial; the exceptions are
// the files under `platform/` that wrap a native API, each of which opts out
// with its own inner attribute. `tests/unsafe_boundary.rs` fails if any file
// in the workspace outside `platform/` re-enables the lint, so the exception
// list is checked rather than described.
#![deny(unsafe_code)]

pub mod capture;
pub mod dns_tcp;
mod error;
pub mod interface;
pub mod link;
pub mod neighbor;
mod platform;
pub mod route;
pub mod transmit;

pub use error::{Error, SendEvidenceFault, SystemFault};
