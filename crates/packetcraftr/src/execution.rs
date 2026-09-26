// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The seams every live workflow shares: the executor contract, validation of
//! the evidence an executor returns, the pacing context that runs each step,
//! and publication of workflow events on the runtime.

mod admission;
mod context;
mod errors;
pub(crate) mod evidence;
mod executor;
pub(crate) mod limits;
mod shared;
mod sink;
pub(crate) mod validation;

pub(crate) use admission::Admission;
pub(crate) use context::{Context, Grant, Paused, Receipt, pause, rate_delay};
pub(crate) use errors::Errors;
pub(crate) use executor::{ExchangeExecutor, Executor, Step};
pub(crate) use executor::{ExecutorFault, WorkflowOverrides};
pub(crate) use shared::Shared;
pub use sink::Sink;
pub(crate) use sink::publisher;
pub use validation::ExchangeEvidenceError;
