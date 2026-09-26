// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exchange: transmitting packets with capture armed first, then collecting
//! the frames correlated to them.
//!
//! [`Client::exchange`](crate::Client::exchange) publishes each outcome as an
//! [`Event`] when its classification becomes final and returns the terminal
//! [`Report`]; a [`Collector`] sink rebuilds the full [`Aggregate`].

mod accumulator;
mod capture;
mod correlation;
mod engine;
mod error;
mod report;
mod request;
mod shutdown;
mod transaction;
mod window;

pub(crate) use accumulator::{
    Accumulator, ProcessContext, ProcessOutcome, WorkflowResponseMatcher, WorkflowStopPredicate,
};
pub(crate) use engine::Prepared;
pub use error::Error;
pub use report::{Aggregate, Collector, Event, Report, Response};
pub(crate) use report::{Observed, into_sent_packet};
pub use request::{Collection, DEFAULT_MAX_RESPONSES, DEFAULT_MAX_UNMATCHED_FRAMES, Request};
pub(crate) use shutdown::CaptureGuard;
pub(crate) use transaction::Transaction;
pub(crate) use window::Window;
