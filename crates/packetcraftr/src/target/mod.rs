// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Live target resolution.

mod model;
mod workflow;

pub use crate::authorization::{Authorizer, PolicyAuthorizer};
pub use model::{Authorized, Error, Family, Hostname, Resolver, SystemResolver, Target};
pub(crate) use workflow::{GateErrors, approve_operation, budgeted, resolve_selected};
