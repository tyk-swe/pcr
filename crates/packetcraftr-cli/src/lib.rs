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
//! | 1. Shared published contract | `output`: types that lower layers or several commands publish |
//! | 2. Foundation | `errors`, `filtering`, `cancellation`, `resources` |
//! | 3. Options | `command_options` |
//! | 4. Invocation | `invocation`: one command's output stream, deadline, cancellation, and diagnostics |
//! | 5. Inputs, system, and presentation | `input`, `system`, `rendering`, `staged_output` |
//! | 6. Commands | `commands`: implementations by `--help` group, each with its own published `output` types, plus the registry and dispatch |
//! | 7. Application shell | `app`: process entry, argument parsing, and help |
//!
//! Three upward edges are deliberate. `output::contract::Command` is generated
//! by the command registry, so published identifiers and the parser come from
//! one declaration. `output::DifferentialReport` lets integration tests build a
//! campaign fixture from the published type. `commands::reference` reads
//! `app::cli` because it documents the application itself.
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

pub use app::run as main;
