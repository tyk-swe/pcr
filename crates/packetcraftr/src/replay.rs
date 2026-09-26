// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy-gated, bounded capture replay, run by
//! [`Client::replay`](crate::Client::replay). Every frame is individually
//! authorized by the client's policy, before and after its route is chosen;
//! malformed traffic requires explicit opt-in.

mod admission;
mod engine;
mod error;
mod evidence;
mod executor;
mod plan;
mod report;
mod request;
#[cfg(test)]
mod tests;

pub use error::Error;
pub use evidence::{FrameEvidence, Transmission};
pub use report::{Aggregate, Collector, Event, Report};
pub use request::{AllFrames, Limits, Options, Request, Selector, Source, Timing};
