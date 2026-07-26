// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The non-bypassable live-traffic authorization boundary.
//!
//! Policy owns destination scope classification, hostname and target models,
//! resolver authorization, packet-declared destination authorization,
//! permissive-packet consent, and per-operation packet/byte budgets.
//!
//! Clients and workflows consume this crate; it never depends on them, so a
//! policy decision cannot be re-derived or weakened by an orchestration layer.

#![forbid(unsafe_code)]

pub mod address;
pub mod target;

mod authorization;
pub(crate) mod contract;

pub use contract::{
    DEFAULT_MAX_RESOLVED_ADDRESSES, MAX_RESOLVED_ADDRESSES, TrafficPolicy, TrafficPolicyError,
};
pub use contract::{TrafficPolicy as Policy, TrafficPolicyError as Error};
