// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic protocol registration.

mod core;

pub use core::{
    Discriminator, FilterFieldBinding, ProtocolRegistry as Registry, RegistryBuilder as Builder,
    RegistryError as Error,
};
pub(crate) use core::{ProtocolRegistry, RegistryBuilder, RegistryError};
