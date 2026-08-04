// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, policy-gated capture replay over injectable timing and I/O seams.
//!
//! Replay retransmits frames from a capture file to reproduce a previously
//! observed exchange against an authorized destination, which is how a
//! protocol bug captured once is turned into a repeatable test. Every frame is
//! authorized individually, and replaying a frame whose dissection preserved
//! malformed bytes additionally requires the explicit malformed-traffic
//! opt-ins.

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
    MAX_REPLAY_DURATION, ReplayAuthorizationContext as AuthorizationContext,
    ReplayAuthorizer as Authorizer, ReplayFrameEvidence as FrameEvidence, ReplayLimits as Limits,
    ReplayOptions as Options, ReplaySelector as Selector, ReplaySummary as Summary,
    ReplayTiming as Timing, ReplayTransmission as Transmission, ReplayTransmitter as Transmitter,
};
pub use system_boundary::{SystemAuthorizer, SystemTransmitter};
