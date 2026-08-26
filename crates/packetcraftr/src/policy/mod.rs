// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Fail-closed live traffic policy for protocol tests and authorized diagnostics.

mod authorization;
mod capture;
mod contract;

pub use capture::CaptureBudget;
pub use contract::{DEFAULT_MAX_RESOLVED_ADDRESSES, MAX_RESOLVED_ADDRESSES};
pub use contract::{Error, Policy};
