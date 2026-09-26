// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy-gated, bounded capture replay. Every frame is individually authorized;
//! malformed traffic requires explicit opt-in.

mod admission;
mod engine;
mod error;
mod evidence;
mod executor;
mod request;
#[cfg(test)]
mod tests;

pub use admission::SystemAuthorizer;
pub use engine::{run_repeated_with_selector, run_with_selector};
pub use error::Error;
pub use executor::SystemTransmitter;
pub use request::{
    FrameEvidence, Limits, Options, Selector, Summary, Timing, Transmission, Transmitter,
};
