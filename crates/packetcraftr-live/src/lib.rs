// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Policy-gated packet transmission and response exchange.

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

pub use client::Client;
pub use packetcraftr_packet::error::BoundaryError;
pub use probe::client_executor::ExchangeExecutor;
pub use send::contract::ClientError as Error;
pub use stats::Stats;
