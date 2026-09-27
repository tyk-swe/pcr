// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic built-in registration. [`registry`](fn@registry) shares the
//! immutable default; [`registry_with`] adds bindings, with
//! [`registry_with_tls_ports`] as the TLS convenience form. Discover codecs and
//! capture roots through [`super::BuiltinProtocol::ALL`] and
//! [`LinkType::BUILTIN_ROOTS`](crate::frame::LinkType::BUILTIN_ROOTS).

mod assembly;
mod bindings;
mod filter_fields;

pub use assembly::{registry, registry_with, registry_with_tls_ports};
pub use bindings::TLS_TCP_PORTS;
