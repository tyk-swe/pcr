// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded offline capture analysis.
//!
//! [`pcap`] handles capture files; [`run`] drives the shared read → dissect →
//! index → filter → dispatch loop; and [`expert`], [`follow`], and [`stats`]
//! consume it. [`reassembly`] is a standalone algorithm API fed by explicit
//! decoded-layer adapters.
//!
//! There is no resolver, route lookup, live-capture, or transmission seam.
//! `packetcraftr-core` depends on neither `packetcraftr-netio` nor
//! `packetcraftr`, so the crate graph enforces this boundary and offline
//! analysis needs no live-traffic authorization gate.
//!
//! Conversation indices are assigned over the whole capture before filtering,
//! so they remain stable across commands. Reassembly consumes only matched
//! frames, keeping a filtered run scoped to the selected conversations.

mod adapter;
mod error;
pub mod expert;
pub mod follow;
pub mod pcap;
mod pipeline;
pub mod reassembly;
pub mod scope;
pub mod stats;
mod stream_index;

pub use error::Error;
pub use pipeline::{FrameRecord, Limits, Options, Summary, run};
