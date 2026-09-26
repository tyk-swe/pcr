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
mod report;
mod request;

pub use error::Error;
pub use report::{Aggregate, Collector, Event, Report, SentFrame};
pub use request::{Options, Request};
