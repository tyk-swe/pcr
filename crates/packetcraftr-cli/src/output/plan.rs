// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use crate::output::network::Plan;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    #[serde(rename = "route")]
    pub plan: Plan,
}

impl From<packetcraftr::route::Plan> for Report {
    fn from(plan: packetcraftr::route::Plan) -> Self {
        Self { plan: plan.into() }
    }
}
