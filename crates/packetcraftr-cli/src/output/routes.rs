// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use crate::output::network::Decision;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub routes: Vec<Decision>,
}

/// One route per interface, in the order the caller listed them.
impl From<Vec<packetcraftr_netio::route::Decision>> for Report {
    fn from(routes: Vec<packetcraftr_netio::route::Decision>) -> Self {
        Self {
            routes: routes.into_iter().map(Into::into).collect(),
        }
    }
}
