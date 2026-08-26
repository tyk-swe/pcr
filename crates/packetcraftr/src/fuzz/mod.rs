// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Authorized, paced live execution of packet-layer fuzz campaigns.

use std::time::Duration;

pub const MAX_RATE: u32 = 1_000_000;
pub const MAX_DURATION: Duration = packetcraftr_netio::capture::MAX_TIMEOUT;

const SYNTHESIZED_ETHERNET_BYTES: u64 = 14;

mod boundary;
mod client_executor;
mod error;
mod execution;
mod request;
mod result;
mod run;
#[cfg(test)]
mod tests;

pub use crate::authorization::PolicyAuthorizer;
pub use boundary::{Execution, ExecutionCase, Executor};
pub use error::Error;
pub use request::{LiveLimits, LiveOptions};
pub use result::{Case, CaseOutcome, Result, Stats, Summary};
pub use run::{run, run_with_events};
