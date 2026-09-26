// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic built-in registration. [`registry`](fn@registry) shares the
//! immutable default; [`registry_with`] adds bindings, with
//! [`registry_with_tls_ports`] as the TLS convenience form. Discover codecs and
//! capture roots through [`super::BuiltinProtocol::ALL`] and
//! [`super::capture::BUILTIN_CAPTURE_ROOTS`].

mod filter;
mod registry;

pub use registry::registration::TLS_TCP_PORTS;
pub use registry::{registry, registry_with, registry_with_tls_ports};
