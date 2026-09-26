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
//! Live workflows run on a [`Client`]. It holds the [`policy::Policy`], the
//! protocol registry, a [`clock::Clock`], the [`progress::Runtime`] that
//! admits event workers, and the [`Providers`] every workflow reaches the
//! network through ([`SystemProviders`] is the native set). Each
//! workflow is admitted by the client's policy, with finite resource limits,
//! before any provider is consulted; an interface selector is resolved only
//! after that. A workflow method takes the workflow's request and a [`Sink`]
//! for its events, publishes each event on a worker admitted by the runtime,
//! and returns its terminal report; the workflow's `Collector` sink rebuilds
//! the full aggregate. [`Client::send`] and [`Client::exchange`] are two such
//! methods.
//!
//! [`route`] plans each packet's route over the client's route provider, and
//! [`neighbor`] resolves an admitted route's next hop over its transmit and
//! capture providers.
//!
//! Every workflow duration and timeout is at most
//! [`packetcraftr_netio::capture::MAX_TIMEOUT`], the longest a capture stays
//! armed for one wait, so no workflow has a ceiling of its own.
//!
//! ```rust
//! use packetcraftr_core::{build, codec, layer::Raw, packet::Packet, protocol};
//!
//! let registry = protocol::builtin::registry();
//! let mut packet = Packet::new();
//! packet.push(Raw::new(vec![0xde, 0xad, 0xbe, 0xef]));
//! let built = build::Builder::new(registry).build(
//!     packet,
//!     codec::Context::default(),
//!     build::Options::default(),
//! )?;
//! assert_eq!(built.bytes.as_ref(), &[0xde, 0xad, 0xbe, 0xef]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

use packetcraftr_core::error::BoundaryError;

mod address;
pub mod capture;
mod client;
pub mod clock;
mod correlation;
pub mod deadline;
pub mod dns;
mod error;
mod evidence;
pub mod exchange;
mod execution;
pub mod fuzz;
mod mtu;
pub mod neighbor;
mod planning;
pub mod policy;
mod preparation;
pub mod probe;
pub mod progress;
mod providers;
pub mod replay;
pub mod route;
pub mod scan;
pub mod send;
mod stats;
pub mod target;
pub mod traceroute;

#[cfg(test)]
mod test_support;

pub use client::Client;
pub use error::Error;
pub use evidence::SentPacket;
pub use execution::{ExchangeEvidenceError, Sink};
pub use providers::{ProviderSet, Providers, SystemProviders};
pub use stats::{Stats, StatsOverflow};
