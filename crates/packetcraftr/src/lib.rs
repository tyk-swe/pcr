// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy-gated live workflows, budgets, and evidence.
//!
//! ```rust,no_run
//! use packetcraftr::{Client, SystemProviders, policy::Policy, send};
//! use packetcraftr_core::{expression, protocol::builtin};
//!
//! let registry = builtin::registry();
//! let packet = expression::parse(
//!     "ipv4(dst=192.0.2.9)/udp(dport=9)/raw(text=ping)",
//!     &registry,
//!     expression::Options::default(),
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
pub mod capture;
mod client;
pub mod clock;
mod correlation;
pub mod deadline;
pub mod dns;
mod error;
pub mod evidence;
pub mod exchange;
mod execution;
pub mod fuzz;
mod mtu;
pub mod neighbor;
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

#[cfg(test)]
mod test_support;

pub use client::Client;
pub use error::Error;
pub use execution::Sink;
pub use providers::{ProviderSet, Providers, SystemProviders};
pub use stats::{Stats, StatsOverflow};
