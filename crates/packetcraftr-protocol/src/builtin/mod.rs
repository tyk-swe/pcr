// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic registration of every codec and capture root declared by the
//! built-in capability manifest.
//!
//! Call [`registry`] for the immutable default registry. For capability
//! discovery, use [`super::support::BUILTIN_PROTOCOL_SUPPORT`] rather than
//! treating successful registration as proof that a workflow builds, dissects,
//! or matches a protocol.

mod filter;
mod registry;

pub use registry::{BuiltinProtocols as Module, default_registry as registry};
