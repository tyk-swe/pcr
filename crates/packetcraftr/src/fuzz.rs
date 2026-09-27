// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Authorized, paced live execution of packet-layer fuzz campaigns.

pub const MAX_RATE: u32 = 1_000_000;

const SYNTHESIZED_ETHERNET_BYTES: u64 = 14;

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
pub use report::{Aggregate, Collector, Event, Evidence, Outcome, Report, Trial};
pub use request::Request;
