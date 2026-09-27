// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Network provider contracts and native backends.
//!
//! All platform-specific and potentially unsafe I/O is contained here.

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
#[cfg(test)]
#[forbid(unsafe_code)]
mod test_support;
#[forbid(unsafe_code)]
pub mod transmit;
#[forbid(unsafe_code)]
mod unsupported;
#[forbid(unsafe_code)]
mod workers;

pub use error::Error;
pub use unsupported::{NativeCapability, Unsupported};
