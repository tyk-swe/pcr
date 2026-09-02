// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Fail-closed live traffic policy for protocol tests and authorized diagnostics.

mod authorization;
mod capture;
mod model;

pub use capture::CaptureBudget;
pub use model::{DEFAULT_MAX_RESOLVED_ADDRESSES, MAX_RESOLVED_ADDRESSES};
pub use model::{Error, Policy};
