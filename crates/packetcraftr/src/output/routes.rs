// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Output contract for the `routes` command.

use serde::Serialize;

pub use crate::output::network::RouteDecisionOutput as Decision;
use crate::output::network::RouteDecisionOutput;

/// Aggregate result of `routes`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RoutesCommandResult {
    pub routes: Vec<RouteDecisionOutput>,
}

pub use RoutesCommandResult as Result;
