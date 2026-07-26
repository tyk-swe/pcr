// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Operating-system implementations of the [`packetcraftr_net`] provider
//! contracts.
//!
//! Every provider here selects a backend from the current target and the
//! explicit native Cargo features. Profiles that exclude a backend still expose
//! the provider type and return an actionable capability error, so composition
//! and command surfaces stay identical across portable and native builds.
//!
//! The private `platform` directory is the only location in the workspace
//! permitted to contain FFI or narrowly reviewed unsafe code; every unsafe
//! block carries its own `SAFETY` explanation.

pub mod capture;
pub mod interface;
pub mod neighbor;
pub mod route;
pub mod transmit;

mod platform;
