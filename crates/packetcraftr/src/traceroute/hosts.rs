// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Traces several authorized hosts under one finite plan, optionally choosing
//! each host's probe from what a scan observed responding and optionally
//! reusing path hops that an earlier host in the same operation learned.

mod engine;
mod planner;
mod report;
mod request;
mod reuse;
mod selection;
#[cfg(test)]
mod tests;

pub use report::{
    Aggregate, Basis, Collector, Event, Host, HostTrace, NotTraced, Report, ReusedHop, Selection,
    State, UndecodedEvidence,
};
pub use request::{Request, Reuse, Strategy};
pub use selection::{Observed, observed};
