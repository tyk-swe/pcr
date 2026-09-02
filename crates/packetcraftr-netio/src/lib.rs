// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Network provider contracts and native I/O adapters.
//!
//! All platform-specific and potentially unsafe I/O is contained here. Higher
//! level transmission and diagnostic workflows remain policy-gated in
//! `packetcraftr`.

// This crate is the only one permitted to contain `unsafe`. Every module
// inherits the denial; the files under `platform/` that wrap a native API opt
// out with their own inner attribute, and `tests/unsafe_boundary.rs` fails if
// any file outside `platform/` re-enables the lint.
#![deny(unsafe_code)]

pub mod capture;
mod error;
pub mod interface;
pub mod link;
pub mod neighbor;
mod platform;
pub mod route;
pub mod transmit;

pub use error::{Error, SendEvidenceFault, SystemFault};

/// Independently owned sender and capture provider composed into the single
/// packet I/O value that capture-before-send exchanges require.
///
/// It implements [`transmit::Sender`] through `sender` and
/// [`capture::Provider`] through `capture`.
#[derive(Clone, Copy, Debug, Default)]
pub struct PacketIo<S, C> {
    pub sender: S,
    pub capture: C,
}

impl<S, C> PacketIo<S, C> {
    pub fn new(sender: S, capture: C) -> Self {
        Self { sender, capture }
    }
}
