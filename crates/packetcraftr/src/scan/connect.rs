// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! TCP connect scan: explicit kernel TCP connects with socket evidence and
//! bounded rolling admission.
//!
//! [`Client::scan_connect`](crate::Client::scan_connect) publishes each
//! settled attempt as an [`Event`] and returns the terminal [`Report`]; a
//! [`Collector`] sink rebuilds the per-endpoint [`Aggregate`].

mod engine;
mod report;
#[cfg(test)]
mod tests;

pub use report::{Aggregate, Collector, Endpoint, Event, Outcome, ProbeEvidence, Report, Stats};
