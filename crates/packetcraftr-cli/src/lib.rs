// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The PacketcraftR command-line application, covering argument parsing, provider
//! composition, workflow dispatch, and rendering through the versioned
//! [`output`] contract.
//!
//! # Layers
//!
//! Modules depend only on their own layer or a lower one:
//!
//! | Layer | Modules |
//! | --- | --- |
//! | 1. Error codes and shared published contract | `code`, `output`, `command_catalog` |
//! | 2. Foundation | `errors`, `filtering`, `cancellation`, `resources` |
//! | 3. Options | `command_options` |
//! | 4. Invocation | `invocation`: one command's output stream, deadline, cancellation, and diagnostics |
//! | 5. Inputs, system, and output channels | `input`, `system`, `staged_output`, `terminal`, `publication`, `capture_output`, `packet_text`, `field_projection` |
//! | 6. Commands | `commands`: implementations by `--help` group, each with its own published `output` types, plus the registry and dispatch |
//! | 7. Application shell | `app`: process entry, argument parsing, and help |
//!
//! The command catalog supplies the parser and the published output contract.
//!
//! Unit tests stay beside the implementations they exercise.
#![forbid(unsafe_code)]

mod app;
mod cancellation;
mod capture_output;
mod code;
mod command_catalog;
mod command_options;
mod commands;
mod errors;
mod field_projection;
mod filtering;
mod input;
mod invocation;
pub mod output;
mod packet_text;
mod publication;
mod resources;
mod staged_output;
mod system;
mod terminal;

pub use app::run as main;
