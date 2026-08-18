// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy-gated, bounded capture replay. Every frame is individually authorized,
//! and packets requiring live opt-in must pass both independent gates.

mod engine;
mod error;
mod model;
mod system_boundary;
#[cfg(test)]
mod tests;
mod wire;

pub use engine::{run, run_with_selector};
pub use error::Error;
pub use model::{
    AuthorizationContext, Authorizer, FrameEvidence, Limits, MAX_REPLAY_DURATION, Options,
    Selector, Summary, Timing, Transmission, Transmitter,
};
pub use system_boundary::{SystemAuthorizer, SystemTransmitter};
