// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Network provider contracts and native backends.
//!
//! All platform-specific and potentially unsafe I/O is contained here.
//!
//! # Layers
//!
//! Modules depend only on their own layer or a lower one:
//!
//! | Layer | Modules |
//! | --- | --- |
//! | 1. Primitives | `deadline`, `link`, `bounded` |
//! | 2. Infrastructure | `unsupported`, `resources`, `workers` |
//! | 3. Provider contracts | `error`, `interface`, `route`, `capture`, `transmit`, `tcp`, `udp`, `tls`, `resolution` |
//! | 4. Native backends | `platform` |
//!
//! The one sanctioned upward edge is dispatch: a contract's system provider
//! calls its `platform` implementation, which in turn returns that contract's
//! types. `platform` is the only module that may contain `unsafe` code; every
//! other module forbids it.
//!
//! Unit tests stay beside the implementations they exercise.

#[forbid(unsafe_code)]
pub mod bounded;
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
pub mod resolution;
#[forbid(unsafe_code)]
pub mod resources;
#[forbid(unsafe_code)]
pub mod route;
#[forbid(unsafe_code)]
pub mod tcp;

#[forbid(unsafe_code)]
pub mod tls;
#[forbid(unsafe_code)]
pub mod transmit;
#[forbid(unsafe_code)]
pub mod udp;
#[forbid(unsafe_code)]
mod unsupported;
#[forbid(unsafe_code)]
mod workers;

pub use error::Error;
pub use unsupported::{NativeCapability, Unsupported};
