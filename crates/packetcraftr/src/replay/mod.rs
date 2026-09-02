// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy-gated, bounded capture replay. Every frame is individually authorized;
//! malformed traffic requires explicit opt-in.

mod authorizer;
mod engine;
mod error;
mod model;
#[cfg(test)]
mod tests;
mod transmitter;
mod wire;

pub use crate::authorization::{Authorizer, Operation, ReplayFrame, WireBudget};
pub use authorizer::SystemAuthorizer;
pub use engine::run_with_selector;
pub use error::Error;
pub use model::{
    FrameEvidence, Limits, MAX_REPLAY_DURATION, Options, Selector, Summary, Timing, Transmission,
    Transmitter,
};
pub use transmitter::SystemTransmitter;
