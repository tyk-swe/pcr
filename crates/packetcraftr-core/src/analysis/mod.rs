// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded offline capture analysis over dissected frames.
//!
//! This module owns the read → dissect → index → filter → dispatch loop the
//! offline analysis commands share, and the adapters that map decoded layers
//! onto the independent reassembly module's inputs. Everything here is offline
//! by design: there is no resolver, route lookup, live capture, or transmission
//! seam, so analysis needs no authorization gates and runs in every build
//! profile.
//!
//! The boundary is enforced by the containing `packetcraftr-core` crate, which
//! depends on neither `packetcraftr-netio` nor `packetcraftr`. A native seam
//! added here therefore fails to build instead of quietly bypassing an
//! authorization gate.
//!
//! Conversation indices are assigned in first-seen order over the whole
//! capture, before any display filter runs, so an index one command reports
//! is the index another command extracts. Reassembly, by contrast, consumes
//! only the frames the filter keeps, so a run narrowed to one conversation
//! buffers only that conversation.

pub(crate) use crate::error::BoundaryError;
pub(crate) use reassembly::tcp::FlowKey;

mod adapter;
mod conversation_index;
mod error;
pub mod expert;
pub mod follow;
pub mod pcap;
mod pipeline;
pub mod reassembly;
pub mod stats;

pub use error::AnalysisError as Error;
use error::AnalysisError;
pub use pipeline::{
    AnalysisLimits as Limits, AnalysisOptions as Options, AnalysisSummary as Summary, FrameRecord,
    run,
};
