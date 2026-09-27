// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The PacketcraftR command-line application: argument parsing, provider
//! composition, workflow dispatch, and rendering through the versioned
//! [`output`] contract.
//!
//! The `packetcraftr` binary only calls [`main`]. JSON compatibility is
//! governed by the published versioned schemas. Rust output types and
//! constructors remain beta APIs and may change between beta releases;
//! importing this crate does not provide a stable workflow facade. Core
//! analysis and native resources keep their canonical owning-crate paths.
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
mod presets;
mod rendering;
mod resources;
mod staged_output;
mod startup;
mod system;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

/// Runs the command-line application with the process arguments and
/// environment, and returns its exit status.
#[must_use]
pub fn main() -> std::process::ExitCode {
    startup::run()
}
