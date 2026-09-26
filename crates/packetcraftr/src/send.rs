// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Send: transmitting every packet a template expands to, a bounded number of
//! passes, under one operation budget.
//!
//! [`Client::send`](crate::Client::send) publishes each confirmed
//! transmission as an [`Event`] and returns the terminal [`Report`]; a
//! [`Collector`] sink rebuilds the full [`Aggregate`].

mod engine;
mod error;
mod evidence;
mod executor;
mod plan;
mod report;
mod request;

pub use error::Error;
pub use evidence::{Event, SentFrame};
pub use report::{Aggregate, Collector, Report};
pub use request::{Options, Request};
