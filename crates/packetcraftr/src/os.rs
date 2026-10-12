// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, policy-gated OS-family fingerprinting of explicit numeric targets.
//!
//! Observed packet fields and qualified candidates remain separate. NAT,
//! firewalls, proxies and configuration can change the observed stack.

mod engine;
mod error;
mod evidence;
mod executor;
mod plan;
mod report;
mod request;
#[cfg(test)]
mod tests;

pub use error::Error;
pub use executor::Preparation;
pub use packetcraftr_core::document::os_fingerprints::{
    Candidate, Match, Observation, Outcome, Probe,
};
pub use report::{Aggregate, Collector, Event, ProbeEvidence, Report};
pub use request::{Limits, Request};

use packetcraftr_core::document::os_fingerprints as core;
use std::sync::Arc;

pub const MAX_ATTEMPTS: u32 = 3;
pub const MAX_PROBES: usize = 32;
pub const MAX_DURATION: std::time::Duration = std::time::Duration::from_secs(30);
pub const MAX_EVIDENCE_FRAMES: usize = core::MAX_OBSERVATIONS;
pub const MAX_EVIDENCE_BYTES: usize = 1024 * 1024;
pub const MAX_FRAME_BYTES: usize = 4096;
pub(crate) const MAX_WIRE_BYTES: u64 = 256;

/// The default corpus contains only signatures backed by the adjacent original
/// capture/provenance record. Empty coverage produces `unknown`, not a guess.
pub fn builtin_corpus() -> Result<Arc<core::Corpus>, core::Error> {
    core::parse(include_bytes!("../data/os-fingerprints.v1.json")).map(Arc::new)
}
