// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Multi-packet capture-ready exchange contracts.

mod accumulator;
mod capture;
mod correlation;
mod engine;
mod report;
mod shutdown;
mod transaction;

pub(crate) use accumulator::{
    Accumulator, ProcessContext, ProcessOutcome, WorkflowResponseMatcher, WorkflowStopPredicate,
};
pub(crate) use engine::Prepared;
pub(crate) use report::into_sent_packet;
pub use report::{
    Collector, DEFAULT_MAX_RESPONSES, DEFAULT_MAX_UNMATCHED_FRAMES, Event, Options, Report,
    Response, Summary,
};
pub(crate) use shutdown::CaptureGuard;
pub(crate) use transaction::Transaction;
