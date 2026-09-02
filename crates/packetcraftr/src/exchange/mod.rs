// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Multi-packet capture-ready exchange contracts.

mod accumulator;
mod capture;
mod client;
mod correlation;
mod model;
mod route_cache;
mod shutdown;
mod transaction;

pub(crate) use accumulator::{
    Accumulator, ProcessContext, ProcessOutcome, WorkflowResponseMatcher, WorkflowStopPredicate,
};
pub(crate) use client::Prepared;
pub(crate) use model::into_sent_packet;
pub use model::{
    Collector, DEFAULT_MAX_RESPONSES, DEFAULT_MAX_UNMATCHED_FRAMES, Event, MAX_EXCHANGE_TIMEOUT,
    Options, Report, Response, Summary,
};
pub(crate) use shutdown::CaptureGuard;
pub(crate) use transaction::Transaction;
