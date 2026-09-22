// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded offline capture analysis. [`pcap`] handles files; [`run`] dissects,
//! indexes, filters, and dispatches to collectors. [`reassembly`] is also
//! available as a standalone algorithm API. Core has no native I/O or
//! live-workflow dependencies.
//!
//! Conversation indices and IP fragment state cover all frames before
//! filtering. A completing frame exposes both its physical layers and
//! reconstructed child layers/transport index to filters. TCP reassembly
//! consumes only matched frames.

mod adapter;
pub mod application;
mod conversation_index;
pub(crate) mod dedup;
pub mod dns;
mod error;
pub mod expert;
pub mod export;
pub mod follow;
pub mod forwarding;
pub mod http;
pub mod pcap;
mod pipeline;
pub mod provenance;
pub mod reassembly;
pub mod scope;
mod serial;
mod session;
pub mod stats;
mod stream;
pub mod tls;

pub use error::Error;
pub use pipeline::{
    ClockReport, Conversation, DerivedDatagram, FrameRecord, IpCounters, IpDatagramOutcome,
    IpEvent, IpEventRecord, IpFamilyCounters, IpReassemblyReport, Limits, Options, Plan, Summary,
    TcpView, UdpView, run, run_with_ip_events,
};
pub use session::{Collector, Needs, Outcome, Pass, Session, SessionError};
pub use stream::{Endpoint, StreamRef, StreamTransport};
