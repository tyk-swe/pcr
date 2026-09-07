// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy-gated live workflows, budgets, and evidence.
//!
//! The intended use is protocol engineering, interoperability testing, and
//! authorized network diagnostics.
//!
//! `packetcraftr-core` owns packets and offline analysis;
//! `packetcraftr-netio` owns provider contracts and native resources.
//! Live entry points such as [`scan`], [`dns`], and [`send`] require a
//! [`policy::Policy`] and finite resource budgets.
//!
//! ```rust
//! use packetcraftr_core::{build, layer::Raw, protocol, Packet};
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

#[cfg(test)]
mod test_fixtures;

pub use client::Client;
pub use error::Error;
pub use evidence::SentPacket;
use packetcraftr_core::error::BoundaryError;
pub use stats::{Stats, StatsOverflow};
