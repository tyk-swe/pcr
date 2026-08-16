// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic protocol registration.

mod binding;
mod builder;
mod error;
mod lookup;
mod validation;

pub use binding::{Discriminator, FilterFieldBinding};
pub use builder::RegistryBuilder as Builder;
pub(crate) use builder::RegistryBuilder;
pub use error::RegistryError as Error;
pub(crate) use error::RegistryError;
pub use lookup::ProtocolRegistry as Registry;
pub(crate) use lookup::ProtocolRegistry;
