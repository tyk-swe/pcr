// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured packet-fuzzing output.

mod model;
pub use crate::frame::{Captured as Frame, Wire};
pub use model::{
    FuzzCaseOutcome as Outcome, FuzzCaseOutput as Case, FuzzCommandResult as Result,
    FuzzMode as Mode, FuzzMutation as Mutation, FuzzReproduction as Reproduction,
    FuzzStrategy as Strategy, FuzzStreamCommandResult as Event,
};
