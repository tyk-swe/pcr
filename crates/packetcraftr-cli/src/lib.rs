// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The PacketcraftR command-line application: argument parsing, provider
//! composition, workflow dispatch, and rendering through the versioned
//! [`output`] contract.
//!
//! Contributor navigation: command implementations live under
//! `src/commands/{packet,files,analyze,network,reference}`. Shared dispatch and
//! security helpers stay at the commands root; output and rendering keep their
//! own modules. Unit tests stay beside the implementations they exercise.
#![forbid(unsafe_code)]

mod cancellation;
mod cli;
mod command_options;
mod commands;
mod errors;
mod filtering;
mod input;
mod invocation;
pub mod output;
mod rendering;
mod resources;
mod staged_output;
mod startup;
mod system;

#[must_use]
pub fn main() -> std::process::ExitCode {
    startup::run()
}
