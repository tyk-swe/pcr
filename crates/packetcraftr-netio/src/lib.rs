// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Network provider contracts and native I/O adapters.
//!
//! All platform-specific and potentially unsafe I/O is contained here. Higher
//! level transmission and diagnostic workflows remain policy-gated in
//! `packetcraftr`.

// This crate is the only one permitted to contain `unsafe`. Non-platform
// modules forbid it locally; files under `platform/` that wrap a native API
// may opt out of the workspace lint with their own inner attribute.

#[forbid(unsafe_code)]
pub mod capture;
#[forbid(unsafe_code)]
pub mod deadline;
#[forbid(unsafe_code)]
mod error;
#[forbid(unsafe_code)]
pub mod interface;
#[forbid(unsafe_code)]
pub mod link;
mod platform;
#[forbid(unsafe_code)]
pub mod resources;
#[forbid(unsafe_code)]
pub mod route;
#[forbid(unsafe_code)]
pub mod tcp;
#[forbid(unsafe_code)]
pub mod transmit;
#[cfg(native_workers)]
#[forbid(unsafe_code)]
mod workers;

pub use error::{Error, SendEvidenceFault, SystemFault};

/// Independently owned transmit and capture providers composed into the single
/// packet I/O value that capture-before-send exchanges require.
///
/// It implements [`transmit::Provider`] through `sender` and
/// [`capture::Provider`] through `capture`.
#[derive(Clone, Copy, Debug, Default)]
pub struct PacketIo<S, C> {
    pub sender: S,
    pub capture: C,
}

#[forbid(unsafe_code)]
impl<S, C> PacketIo<S, C> {
    pub fn new(sender: S, capture: C) -> Self {
        Self { sender, capture }
    }
}
