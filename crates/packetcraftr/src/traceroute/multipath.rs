// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Finite, flow-preserving traceroute sweeps. Adjacencies are observations
//! from separate probes, not proof of physical links or exhaustive ECMP discovery.

mod engine;
mod executor;
mod packet;
mod report;
mod request;
#[cfg(test)]
mod tests;
mod topology;

pub use report::{
    Aggregate, Change, Collector, Edge, Event, Flow, FlowCompletion, FlowSummary, Node, NodeKey,
    ProbeEvidence, Reply, Report, Rtt, Summary, TopologyUpdate, Unmatched,
};
pub use request::Request;
pub const DEFAULT_FLOWS: u16 = 16;
pub const MAX_FLOWS: u16 = 64;
