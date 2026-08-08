// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Response-correlation extension contracts.

mod contract;

pub use contract::{MatchResult as Result, ResponseMatcher as Matcher};
pub(crate) use contract::{MatchResult, ResponseMatcher};
