// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Authorized, paced live execution of packet-layer fuzz campaigns.

use std::time::Duration;

pub const MAX_RATE: u32 = 1_000_000;
pub const MAX_DURATION: Duration = packetcraftr_netio::capture::MAX_TIMEOUT;

const SYNTHESIZED_ETHERNET_BYTES: u64 = 14;

mod error;
mod evidence;
mod execution;
mod executor;
mod model;
mod plan;
mod run;
#[cfg(test)]
mod tests;

pub use crate::authorization::PolicyAuthorizer;
pub use crate::probe::Executor;
pub use error::Error;
pub use execution::{Execution, ExecutionCase};
pub use model::{Case, CaseOutcome, LiveLimits, LiveOptions, Report, Stats, Summary};
pub use run::{RunInput, run, run_offline_with_events, run_with_events};
