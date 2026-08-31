// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Output contract for the `plan` command.

use serde::Serialize;

use crate::output::network::Plan;

/// Aggregate result of `plan`.
///
/// The key `route` is used at two nesting levels in opposite directions: here
/// it renames the whole [`Plan`], and inside that plan it renames
/// [`Plan::decision`]. So `result.route` is the plan and `result.route.route`
/// is the route decision the plan was built from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    #[serde(rename = "route")]
    pub plan: Plan,
}
