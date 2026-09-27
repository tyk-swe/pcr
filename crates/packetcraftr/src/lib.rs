// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy-gated live workflows, budgets, and evidence.
//!
//! The intended use is protocol engineering, interoperability testing, and
//! authorized network diagnostics.
//!
//! `packetcraftr-core` owns packets and offline analysis;
//! `packetcraftr-netio` owns provider contracts and native resources.
//!
//! # The client
//!
//! Every live workflow runs on a [`Client`]: [`send`], [`exchange`], [`dns`],
//! [`scan`] (and its TCP [`scan::connect`] variant), [`traceroute`], [`fuzz`],
//! [`replay`], and [`capture`]. The client holds the [`policy::Policy`], the
//! protocol registry, a [`clock::Clock`], the [`runtime::Runtime`] that admits
//! event workers, an optional cancellation signal, and the [`Providers`]
//! every workflow reaches the network through: a [`ProviderSet`] of route,
//! interface, capture, transmit, TCP, and resolver providers, or
//! [`SystemProviders`] for the native ones.
//!
//! A workflow method takes the workflow's `Request` and a [`Sink`] for its
//! events, and returns its terminal `Report`. The client admits the request
//! through its policy, with finite limits, before any provider is consulted;
//! an interface selector is resolved and a declared target is resolved only
//! after that. Each event reaches the sink on a worker the runtime admits, and
//! the workflow waits for the sink's answer before it continues. The
//! workflow's `Collector` is a sink that rebuilds the full `Aggregate` of
//! every event joined with the report.
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
//!
//! # Workflow roles
//!
//! Each workflow module splits its work into the same roles, named as in the
//! project glossary: the `request` a caller validates, the `plan` of bounded
//! steps derived from it before any traffic leaves, the `engine` that runs the
//! plan on the client, the `executor` that carries out one approved step
//! against the providers, the `evidence` a step produced and its validation,
//! the `report`, `Event`, `Aggregate`, and `Collector` it publishes, and its
//! one `Error`. Engines and executors are internal: the client is the only way
//! to run a workflow.
//!
//! [`route`] plans each packet's route over the client's route provider, and
//! [`neighbor`] resolves an admitted route's next hop over its transmit and
//! capture providers. [`probe`] holds the probe vocabulary scan and traceroute
//! share.
//!
//! Every workflow duration and timeout is at most
//! [`packetcraftr_netio::capture::MAX_TIMEOUT`], the longest a capture stays
//! armed for one wait, so no workflow has a ceiling of its own.

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
