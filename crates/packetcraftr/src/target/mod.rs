// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Live target resolution.

mod authorization;
mod model;

pub use model::{Authorized, Error, Family, Hostname, Resolver, SystemResolver, Target};
pub(crate) use authorization::{approve_operation, resolve_selected};
