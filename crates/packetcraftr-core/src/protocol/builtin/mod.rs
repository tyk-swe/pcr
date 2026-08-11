// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic registration of every codec and capture root declared by the
//! built-in capability tables.
//!
//! Call [`registry`] for the immutable default registry. For codec and capture
//! discovery, use [`super::support::BUILTIN_PROTOCOLS`] and
//! [`super::support::BUILTIN_CAPTURE_ROOTS`].

mod filter;
mod registry;

pub use registry::default_registry as registry;
