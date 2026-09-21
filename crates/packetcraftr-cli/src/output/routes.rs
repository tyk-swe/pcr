// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use crate::output::network::Decision;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub routes: Vec<Decision>,
}
