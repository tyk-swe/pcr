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
mod evidence;
mod executor;
mod plan;
mod report;
mod request;
mod shutdown;
mod window;

pub(crate) use accumulator::{
    Accumulator, ProcessContext, ProcessOutcome, WorkflowResponseMatcher, WorkflowStopPredicate,
};
pub use error::Error;
pub use evidence::{Event, Response};
pub(crate) use evidence::{Observed, into_sent_packet};
pub(crate) use plan::Prepared;
pub use report::{Aggregate, Collector, Report};
pub use request::{Collection, DEFAULT_MAX_RESPONSES, DEFAULT_MAX_UNMATCHED_FRAMES, Request};
pub(crate) use shutdown::CaptureGuard;
pub(crate) use window::Window;
