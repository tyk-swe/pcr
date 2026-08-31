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

pub(crate) use crate::materialize::PreparedPacket;
pub(crate) use accumulator::{
    Accumulator, ProcessContext, ProcessOutcome, WorkflowResponseMatcher, WorkflowStopPredicate,
};
pub(crate) use contract::into_sent_packet;
pub use contract::{
    Collector, DEFAULT_MAX_RESPONSES, DEFAULT_MAX_UNMATCHED_FRAMES, Event, MAX_EXCHANGE_TIMEOUT,
    Options, Report, Response, Summary,
};
pub(crate) use preparation::Prepared;
pub(crate) use shutdown::CaptureGuard;
pub(crate) use transaction::Transaction;
