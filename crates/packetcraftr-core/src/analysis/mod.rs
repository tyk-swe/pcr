// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded offline capture analysis.
//!
//! [`pcap`] handles capture files; [`run`] drives the shared read → dissect →
//! index → filter → dispatch loop; and [`expert`], [`follow`], [`stats`], and
//! [`tls`] consume it. [`reassembly`] is a standalone algorithm API fed by
//! explicit decoded-layer adapters.
//!
//! There is no resolver, route lookup, live-capture, or transmission seam.
//! `packetcraftr-core` depends on neither `packetcraftr-netio` nor
//! `packetcraftr`, so the crate graph enforces this boundary and offline
//! analysis needs no live-traffic authorization gate.
//!
//! Conversation indices are assigned over the whole capture before filtering,
//! so they remain stable across commands. IP fragments update capture-global
//! bounded state before filtering. On a completing physical frame, display
//! filters retain that frame's decoded layers and facts while also seeing the
//! reconstructed datagram's child layers and derived transport index. TCP
//! reassembly still consumes only matched frames, keeping its stream buffers
//! scoped to the filter.

mod adapter;
mod conversation_index;
pub(crate) mod dedup;
mod error;
pub mod expert;
pub mod follow;
pub mod pcap;
mod pipeline;
pub mod reassembly;
pub mod scope;
pub mod stats;
pub mod tls;

pub use error::Error;
pub use pipeline::{
    DerivedDatagram, FrameRecord, IpCounters, IpDatagramOutcome, IpEvent, IpEventRecord,
    IpFamilyCounters, IpReassemblyReport, Limits, Options, Summary, run, run_with_ip_events,
};
