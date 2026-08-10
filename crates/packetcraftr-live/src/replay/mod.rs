// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy-gated, bounded capture replay. Every frame is individually authorized;
//! malformed traffic requires explicit opt-in.

mod engine;
mod error;
mod model;
mod system_boundary;
#[cfg(test)]
mod tests;
mod wire;

pub use engine::{replay_capture as run, replay_capture_with_selector as run_with_selector};
pub use error::ReplayError as Error;
pub use model::{
    MAX_REPLAY_DURATION, NonmonotonicTimestampPolicy,
    ReplayAuthorizationContext as AuthorizationContext, ReplayAuthorizer as Authorizer,
    ReplayFrameEvidence as FrameEvidence, ReplayLimits as Limits, ReplayOptions as Options,
    ReplaySelector as Selector, ReplaySummary as Summary, ReplayTiming as Timing,
    ReplayTransmission as Transmission, ReplayTransmitter as Transmitter, TimestampAdjustment,
};
pub use system_boundary::{SystemAuthorizer, SystemTransmitter};
