// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic, bounded, field-aware packet mutation.
//!
//! [`run`] is deliberately offline: its signature has no resolver, route, or
//! native-I/O seam. [`run_live`] is a separate, explicit entry point that
//! requires operation authorization and a capture-ready executor.

use std::time::Duration;

use packetcraftr_packet::template::DEFAULT_MAX_TEMPLATE_PACKETS;

pub const DEFAULT_FUZZ_CASES: usize = 64;
pub const DEFAULT_MAX_FUZZ_CASES: usize = DEFAULT_MAX_TEMPLATE_PACKETS;
pub const MAX_FUZZ_CASES: usize = 100_000;
pub const DEFAULT_MAX_FUZZ_FIELD_BYTES: usize = 4 * 1024;
pub const MAX_FUZZ_FIELD_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_FUZZ_LIST_ITEMS: usize = 256;
pub const MAX_FUZZ_LIST_ITEMS: usize = 4_096;
pub const DEFAULT_MAX_FUZZ_SHRINK_STEPS: usize = 8;
pub const MAX_FUZZ_SHRINK_STEPS: usize = 64;
pub const MAX_FUZZ_RATE: u32 = 1_000_000;
pub const MAX_FUZZ_DURATION: Duration = packetcraftr_net::capture::MAX_TIMEOUT;
pub const MAX_FUZZ_STRATEGIES: usize = 4;
pub const MAX_FUZZ_TARGET_FIELDS: usize = 4_096;

const SYNTHESIZED_ETHERNET_BYTES: u64 = 14;
const SPLITMIX_INCREMENT: u64 = 0x9e37_79b9_7f4a_7c15;
const CASE_DOMAIN: u64 = 0xd1b5_4a32_d192_ed03;

mod client_executor;
mod engine;
mod error;
mod execution;
mod model;
mod mutation;
#[cfg(test)]
mod tests;

pub use client_executor::PolicyAuthorizer;
pub use engine::{fuzz as run, fuzz_live as run_live};
pub use error::FuzzError as Error;
pub use model::{
    FuzzAuthorizer as Authorizer, FuzzCase as Case, FuzzCaseExecution as Execution,
    FuzzCaseFailure as CaseFailure, FuzzCaseOutcome as CaseOutcome,
    FuzzExecutionCase as ExecutionCase, FuzzExecutor as Executor, FuzzLimits as Limits,
    FuzzLiveOptions as LiveOptions, FuzzMode as Mode, FuzzMutation as Mutation,
    FuzzRequest as Request, FuzzResult as Result, FuzzStats as Stats, FuzzStrategy as Strategy,
    FuzzTarget as Target, FuzzTargetParseError as TargetParseError,
};
/// Executes fuzz cases through a client's capture-ready exchange lifecycle.
pub type ClientExecutor<'a, R, N, I> =
    crate::probe::client_executor::ClientExecutor<'a, R, N, I, crate::probe::client_executor::Fuzz>;
