// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded offline capture analysis.

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
pub mod http2;
mod pipeline;
pub mod provenance;
pub mod reassembly;
pub mod scope;
mod serial;
mod session;
pub mod stats;
mod stream;
pub mod tls;

pub use error::{Constraint, Error};
pub use pipeline::{
    ClockReport, Conversation, DerivedDatagram, FrameRecord, IpCounters, IpDatagramOutcome,
    IpEvent, IpEventRecord, IpFamilyCounters, IpReassemblyReport, Limits, Options, Plan, Summary,
    TcpView, UdpView, run, run_with_ip_events,
};
pub use session::{Collector, CollectorNeeds, Outcome, Pass, Session};
pub use stream::{Endpoint, StreamRef, StreamTransport};
