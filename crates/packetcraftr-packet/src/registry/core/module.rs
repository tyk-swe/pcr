// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::builder::RegistryBuilder;
use super::error::RegistryError;

/// A compile-time Rust extension module.
pub trait ProtocolModule {
    fn register(&self, builder: &mut RegistryBuilder) -> Result<(), RegistryError>;
}
