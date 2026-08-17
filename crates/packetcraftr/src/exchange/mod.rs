// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Multi-packet capture-ready exchange contracts.

mod accumulator;
mod capture;
mod contract;
mod correlation;
mod execution;
mod finalization;
mod options;
mod preparation;
mod retention;
mod route_cache;
mod send_sequence;
mod shutdown;
mod transaction;

pub(crate) use accumulator::{
    Accumulator, ProcessContext, ProcessOutcome, WorkflowPromotionContext, WorkflowResponseMatcher,
};
pub use contract::{
    DEFAULT_MAX_RESPONSES, DEFAULT_MAX_UNMATCHED_FRAMES, MAX_EXCHANGE_TIMEOUT, Options, Response,
    Result,
};
pub(crate) use preparation::{Prepared, PreparedPacket};
pub(crate) use shutdown::CaptureGuard;
pub(crate) use transaction::Transaction;
