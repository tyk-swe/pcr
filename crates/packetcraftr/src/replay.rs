// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy-gated, bounded capture replay, run by
//! [`Client::replay`](crate::Client::replay). A request's optional
//! [`FrameSelector`](packetcraftr_core::filter::FrameSelector) picks the
//! frames and its [`Routing`] picks each one's output interface. Every frame
//! is individually authorized by the client's policy, before and after its
//! route is chosen; malformed traffic requires explicit opt-in.

mod admission;
mod engine;
mod error;
mod evidence;
mod executor;
mod plan;
mod report;
mod request;
mod routing;
#[cfg(test)]
mod tests;

pub use error::Error;
pub use evidence::{FrameEvidence, Transmission};
pub use report::{Aggregate, Collector, Event, Report};
pub use request::{Limits, Options, Request, Source, Timing};
pub use routing::{Condition, MAX_RULES, Routing, Rule, RuleError};
