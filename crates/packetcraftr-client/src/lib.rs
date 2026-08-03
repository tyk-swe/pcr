// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Policy-gated packet transmission and response exchange.

mod address;
mod authorization;
mod client;
mod evidence;
pub mod exchange;
mod materialize;
mod planning;
pub mod policy;
pub mod send;
mod stats;
pub mod target;
mod validation;

#[cfg(test)]
mod tests;

pub use client::Client;
pub use send::contract::ClientError as Error;
pub use stats::Stats;
