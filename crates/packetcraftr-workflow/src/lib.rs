// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Bounded packet workflows with explicit offline and live entry points.
//!
//! [`scan`], [`traceroute`], [`dns`], and [`replay`] are live domains: their
//! public entry points require authorization and finite operation budgets.
//! [`fuzz::run`] is deliberately offline, while [`fuzz::run_live`] makes its
//! registry, authorization, execution, and clock boundaries explicit. Shared
//! probe mechanics own only the batch lifecycle, wire correlation, and exact
//! evidence accounting used across live domains; targets and clocks have
//! explicit top-level owners, while packet generation, validation, and
//! classification remain with each workflow.

pub mod clock;
pub mod dns;
pub mod fuzz;
mod probe;
pub mod replay;
pub mod scan;
pub mod target;
pub mod traceroute;

pub use packetcraftr_client::Stats;
pub use packetcraftr_core::error::BoundaryError;
pub use target::AddressFamily;
