// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The `packetcraftr` command-line surface: arguments, command handlers,
//! input parsing, rendering, and runtime composition.
//!
//! [`run_entrypoint`] is the single entry point the `packetcraftr` binary
//! launches. Everything else stays private so the executable's behaviour is
//! defined here rather than assembled by its launcher.

#![forbid(unsafe_code)]

mod arguments;
mod commands;
mod errors;
mod input;
mod rendering;
mod runtime;

pub use runtime::run_entrypoint;

#[cfg(test)]
mod tests;
