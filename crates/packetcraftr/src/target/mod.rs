// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Live target resolution.

mod contract;
mod workflow;

pub use contract::{Authorized, Error, Family, Hostname, Resolver, SystemResolver, Target};
pub use workflow::{Authorizer, PolicyAuthorizer};
pub(crate) use workflow::{approve_operation, resolve_selected};
