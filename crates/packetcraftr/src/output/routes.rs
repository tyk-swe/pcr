// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Output contract for the `routes` command.

use serde::Serialize;

use crate::output::network::Decision;

/// Aggregate result of `routes`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Result {
    pub routes: Vec<Decision>,
}
