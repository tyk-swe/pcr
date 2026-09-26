// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Authorized, paced live execution of packet-layer fuzz campaigns.

pub const MAX_RATE: u32 = 1_000_000;

const SYNTHESIZED_ETHERNET_BYTES: u64 = 14;

mod error;
mod evidence;
mod execution;
mod executor;
mod plan;
mod report;
mod request;
mod engine;
#[cfg(test)]
mod tests;

pub use error::Error;
pub use execution::{Execution, ExecutionCase};
pub use report::{Case, CaseOutcome, IncoherentReport, Report, Stats, Summary, Totals};
pub use request::{LiveLimits, LiveOptions};

pub use engine::{RunInput, run, run_offline_with_events, run_with_events};
