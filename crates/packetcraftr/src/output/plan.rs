// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Output contract for the `plan` command.

use serde::Serialize;

use crate::output::network::Plan;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Result {
    #[serde(rename = "route")]
    pub plan: Plan,
}
