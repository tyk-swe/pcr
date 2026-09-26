// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The seams every live workflow shares: the executor contract, validation of
//! the evidence an executor returns, the pacing context that runs each step,
//! and publication of workflow events on the runtime.

mod context;
mod errors;
pub(crate) mod evidence;
mod executor;
pub(crate) mod limits;
mod sink;
pub(crate) mod validation;

pub(crate) use context::{Context, Grant, Paused, Receipt, pause};
pub(crate) use errors::Errors;
pub use executor::{ExchangeExecutor, Executor, PipelineEvent, PipelineOptions, Request};
pub(crate) use executor::{ExecutorFault, WorkflowOverrides};
pub(crate) use sink::sink_observer;
pub use validation::ExchangeEvidenceError;
