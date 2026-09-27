// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The PacketcraftR command-line application: argument parsing, provider
//! composition, workflow dispatch, and rendering through the versioned
//! [`output`] contract.
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
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

#[must_use]
pub fn main() -> std::process::ExitCode {
    startup::run()
}
