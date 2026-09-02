// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy-gated live workflows and versioned, render-neutral output.
//!
//! The intended use is protocol engineering, interoperability testing, and
//! authorized network diagnostics.
//!
//! [`core`] exposes portable packet mechanics, [`analysis`] exposes offline
//! capture analysis, and [`netio`] exposes provider contracts and native I/O.
//! Live entry points such as [`scan`], [`dns`], and [`send`] require a
//! [`policy::Policy`] and finite resource budgets.
//!
//! ```rust
//! use packetcraftr::core::{build, layer::Raw, protocol, Packet};
//!
//! let registry = protocol::builtin::registry();
//! let mut packet = Packet::new();
//! packet.push(Raw::new(vec![0xde, 0xad, 0xbe, 0xef]));
//! let built = build::Builder::new(registry).build(
//!     packet,
//!     build::Context::default(),
//!     build::Options::default(),
//! )?;
//! assert_eq!(built.bytes.as_ref(), &[0xde, 0xad, 0xbe, 0xef]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod address;
pub mod authorization;
mod client;
pub mod clock;
pub mod dns;
mod error;
mod evidence;
pub mod exchange;
pub mod fuzz;
mod materialize;
mod mtu;
mod planning;
pub mod policy;
pub mod probe;
pub mod progress;
pub mod replay;
pub mod scan;
pub mod send;
mod stats;
pub mod target;
pub mod traceroute;

pub mod output;

#[cfg(test)]
mod test_fixtures;

pub use client::Client;
pub use error::Error;
pub use evidence::SentPacket;
pub use packetcraftr_core as core;
pub use packetcraftr_core::analysis;
pub use packetcraftr_core::error::BoundaryError;
pub use packetcraftr_netio as netio;
pub use probe::ExchangeExecutor;
pub use probe::{EPHEMERAL_SOURCE_PORT_BASE, ephemeral_source_port};
pub use stats::{Stats, StatsOverflow};
