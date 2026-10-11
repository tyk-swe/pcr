// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! A scan's follow-ups, run under the scan's own budget: a trace of every
//! scanned host and a reverse-DNS lookup of each.

mod engine;
mod error;
mod report;
mod request;
mod reverse;
#[cfg(test)]
mod tests;
mod trace;

pub use error::Error;
pub use report::{Aggregate, Collector, ConnectReport, Event, Report};
pub use request::{ConnectRequest, Request, ReverseDns, Trace};
pub use reverse::{ReverseLookup, ReverseLookups};
