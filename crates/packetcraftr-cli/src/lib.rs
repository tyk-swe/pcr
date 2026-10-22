// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The PacketcraftR command-line application: argument parsing, provider
//! composition, workflow dispatch, and rendering through the versioned
//! [`output`] contract.
//!
//! # Layers
//!
//! Modules depend only on their own layer or a lower one:
//!
//! | Layer | Modules |
//! | --- | --- |
//! | 1. Published contract | `output` |
//! | 2. Foundation | `errors`, `filtering`, `cancellation`, `resources` |
//! | 3. Options | `command_options` |
//! | 4. Invocation | `invocation`: one command's output stream, deadline, cancellation, and diagnostics |
//! | 5. Inputs, system, and presentation | `input`, `system`, `rendering`, `staged_output` |
//! | 6. Commands | `commands`: implementations by `--help` group, the registry, and dispatch |
//! | 7. Application shell | `app`: process entry, argument parsing, and help |
//!
//! Two upward edges are deliberate. `output::contract::Command` is generated
//! by the command registry, so published identifiers and the parser come from
//! one declaration. `commands::reference` reads `app::cli` because it
//! documents the application itself.
//!
//! Unit tests stay beside the implementations they exercise.
#![forbid(unsafe_code)]

mod app;
mod cancellation;
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
mod system;

#[must_use]
pub fn main() -> std::process::ExitCode {
    app::run()
}
