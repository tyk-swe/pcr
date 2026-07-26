// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic registration of every codec and capture root declared by the
//! built-in capability manifest.
//!
//! Call [`catalog`] for the immutable default catalog. For capability
//! discovery, use [`super::support::BUILTIN_PROTOCOL_SUPPORT`] rather than
//! treating successful registration as proof that a workflow builds, dissects,
//! or matches a protocol.

mod catalog;

pub use catalog::{BuiltinProtocols as Module, default_catalog as catalog};
