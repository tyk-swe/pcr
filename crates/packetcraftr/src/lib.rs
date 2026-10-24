// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy-gated live workflows, budgets, and evidence.
//!
//! # Layers
//!
//! Modules depend only on their own layer or a lower one:
//!
//! | Layer | Modules |
//! | --- | --- |
//! | 1. Foundation | `clock`, `deadline`, `engine::stats`, `engine::correlation` |
//! | 2. Environment | `error`, `policy`, `target` (model and selection), `route`, `neighbor`, `providers`, `runtime`, `client` |
//! | 3. Engine | `engine::{admission, planning, preparation, execution}`, `evidence` |
//! | 4. Primitives | `send`, `exchange`, `capture`, `probe` |
//! | 5. Workflows | `dns`, `traceroute`, `os`, `identify`, `replay`, `fuzz`, `audit`, `target::plan` |
//! | 6. Composite | `scan`, which follows up with traces and reverse DNS |
//!
//! `engine` is private plumbing every live workflow shares. A type a lower
//! layer defines may be re-exported under the workflow that names it, such as
//! `send::Options`, `exchange::Response`, and `scan::{Reply, Stage}`.
//! Hand-offs from scan results to later workflows live with `scan`, for
//! example `scan::Aggregate::trace_observations`.
//!
//! The one deliberate cycle is `policy` and `target`: policy resolves and
//! authorizes targets, and a target error can carry the policy refusal behind it.
//!
//! Each `impl Client` block lives with the module that owns its operation.
//!
//! Unit tests stay beside the implementations they exercise.
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

pub mod audit;
pub mod capture;
mod client;
pub mod clock;
pub mod deadline;
pub mod dns;
mod engine;
mod error;
pub mod evidence;
pub mod exchange;
pub mod fuzz;
pub mod identify;
pub mod neighbor;
pub mod os;
pub mod policy;
pub mod probe;
mod providers;
pub mod replay;
pub mod route;
pub mod runtime;
pub mod scan;
pub mod send;
pub mod target;
pub mod traceroute;

pub use client::Client;
pub use engine::execution::{Delivery, Sink};
pub use engine::stats::{Stats, StatsOverflow};
pub use error::{Error, NeighborSpent};
pub use providers::{
    CaptureProviders, PacketProviders, ProviderSet, SystemProviders, TargetProviders, TcpProviders,
    TransmitProviders, TransmitSet, UdpProviders,
};

#[cfg(test)]
mod network_improvements;
