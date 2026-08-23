// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Authorized, paced live execution of packet-layer fuzz campaigns.

use std::time::Duration;

pub const MAX_RATE: u32 = 1_000_000;
pub const MAX_DURATION: Duration = packetcraftr_netio::capture::MAX_TIMEOUT;

const SYNTHESIZED_ETHERNET_BYTES: u64 = 14;

mod client_executor;
mod engine;
mod execution;
mod model;
#[cfg(test)]
mod tests;

pub use engine::{run, run_with_events};
pub use model::{
    Case, CaseOutcome, Execution, ExecutionCase, Executor, Limits, Options, Result, Stats, Summary,
};
