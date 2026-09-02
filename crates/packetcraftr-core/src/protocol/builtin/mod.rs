// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic registration of every codec and capture root declared by the
//! built-in capability tables.
//!
//! Call [`registry`] for the immutable default registry. For codec and capture
//! discovery, use [`super::BuiltinProtocol::ALL`] and
//! [`super::capture::BUILTIN_CAPTURE_ROOTS`].
//!
//! [`registry_with`] is the seam for callers that need one more binding than
//! the defaults — remapping a service onto a non-standard port, for instance.
//! [`registry_with_tls_ports`] is the ready-made form of that for TLS.

mod filter;
mod registry;

pub use registry::registration::TLS_TCP_PORTS;
pub use registry::{registry, registry_with, registry_with_tls_ports};
