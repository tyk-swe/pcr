// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Authorized, paced execution of a prepared packet fuzz campaign.
//!
//! Deterministic mutation and offline execution live in
//! [`packetcraftr_packet::fuzz`]. [`run`] prepares exactly that packet-layer
//! campaign before adding authorization, transmission, and capture evidence.

use std::time::Duration;

pub const MAX_RATE: u32 = 1_000_000;
pub const MAX_DURATION: Duration = packetcraftr_network::capture::MAX_TIMEOUT;

const SYNTHESIZED_ETHERNET_BYTES: u64 = 14;

mod boundary;
mod client_executor;
mod decode;
mod error;
mod execution;
mod request;
mod result;
mod run;
#[cfg(test)]
mod tests;

pub use boundary::{
    FuzzAuthorizer as Authorizer, FuzzCaseExecution as Execution,
    FuzzExecutionCase as ExecutionCase, FuzzExecutor as Executor,
};
pub use client_executor::PolicyAuthorizer;
pub use error::FuzzError as Error;
pub use request::LiveOptions;
pub use result::{Case, CaseOutcome, Mode, Result, Stats};
pub use run::run;
