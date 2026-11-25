// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic response selection shared by live workflows.

mod selection;

pub use selection::Response;
pub(crate) use selection::{
    CandidateKey, Passed, ResponseCandidate, ResponseSelector, Selected, candidate_precedes,
};
