// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy-gated live workflows and versioned, render-neutral output.
//!
//! Runtime-neutral packet mechanics and offline analysis live in
//! [`core`] and [`analysis`]. Native provider contracts and adapters live in
//! [`netio`]. Live entry points such as [`scan`], [`dns`], and [`send`] require
//! a [`policy::Policy`] and finite resource budgets.
//!
//! ```text
//! use std::sync::Arc;
//! use packetcraftr::core::{build, layer::Raw, protocol, Packet};
//!
//! let registry = Arc::new(protocol::builtin::registry()?);
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
mod authorization;
mod client;
pub mod clock;
pub mod dns;
mod evidence;
pub mod exchange;
pub mod fuzz;
mod materialize;
mod planning;
pub mod policy;
mod probe;
pub mod replay;
pub mod scan;
pub mod send;
mod stats;
pub mod target;
pub mod traceroute;
mod validation;

pub mod output;

pub use client::Client;
pub use evidence::SentPacket;
pub use packetcraftr_core as core;
pub use packetcraftr_core::analysis;
pub use packetcraftr_core::error::BoundaryError;
pub use packetcraftr_netio as netio;
pub use probe::client_executor::ExchangeExecutor;
pub use send::contract::ClientError as Error;
pub use stats::Stats;

fn live_timestamp(frame: &packetcraftr_core::frame::Frame) -> std::time::SystemTime {
    frame
        .timestamp
        .expect("live capture and transmission adapters always timestamp evidence frames")
}
