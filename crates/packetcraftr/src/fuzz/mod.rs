// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Authorized, paced live execution of packet-layer fuzz campaigns.

use std::time::Duration;

pub const MAX_RATE: u32 = 1_000_000;
pub const MAX_DURATION: Duration = packetcraftr_netio::capture::MAX_TIMEOUT;

const SYNTHESIZED_ETHERNET_BYTES: u64 = 14;

mod client_executor;
mod error;
mod evidence;
mod execution;
mod plan;
mod report;
mod request;
mod run;
#[cfg(test)]
mod tests;

pub use crate::authorization::PolicyAuthorizer;
pub use error::Error;
pub use execution::{Execution, ExecutionCase, Executor};
pub use report::{Case, CaseOutcome, Report, Stats, Summary};
pub use request::{LiveLimits, LiveOptions};
pub use run::{RunInput, run, run_with_events};
