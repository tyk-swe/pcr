// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy-gated live workflows, budgets, and evidence.
//!
//! Contributor navigation: `tests/integration/main.rs` registers the `dns`,
//! `policy`, `scan`, `send`, and `audit` domains in one binary. Shared providers
//! register through `tests/common.rs`; scanner fixture conditions and providers
//! stay in `tests/common/scanner_fixture/`, where examples also import them.
//!
//! ```rust,no_run
//! use packetcraftr::{Client, SystemProviders, policy::Policy, send};
//! use packetcraftr_core::{expression, protocol::builtin};
//!
//! let registry = builtin::registry();
//! let packet = expression::parse(
//!     "ipv4(dst=192.0.2.9)/udp(dport=9)/raw(text=ping)",
//!     &registry,
//!     expression::Limits::default(),
//! )?;
//! let client = Client::new(registry, Policy::default(), SystemProviders);
//! let collector = send::Collector::default();
//! let report = client.send(
//!     send::Request::packet(packet, send::Options::default()),
//!     collector.clone(),
//! )?;
//! let aggregate = collector.finish(report)?;
//! println!("sent {} bytes", aggregate.stats.bytes);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod address;
pub mod audit;
pub mod capture;
mod client;
pub mod clock;
mod correlation;
pub mod deadline {
    /// Allowance for a passive route or interface lookup whose operation has no deadline.
    pub const PASSIVE_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
}
pub mod dns;
mod error;
pub mod evidence;
pub mod exchange;
mod execution;
pub mod fuzz;
pub mod identify;
mod mtu;
pub mod neighbor;
pub mod os;
mod planning;
pub mod policy;
mod preparation;
pub mod probe;
mod providers;
pub mod replay;
pub mod route;
pub mod runtime;
pub mod scan;
pub mod send;
mod stats;
pub mod target;
pub mod traceroute;

pub use client::Client;
pub use error::{Error, NeighborSpent};
pub use execution::{Delivery, Sink};
pub use providers::{
    CaptureProviders, PacketProviders, ProviderSet, SystemProviders, TargetProviders, TcpProviders,
    TransmitProviders, TransmitSet, UdpProviders,
};
pub use stats::{Stats, StatsOverflow};
