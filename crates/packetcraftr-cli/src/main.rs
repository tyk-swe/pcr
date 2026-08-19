// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Process entry point for argument parsing, provider composition, workflow
//! dispatch, and rendering through the versioned [`packetcraftr::output`]
//! contract.

#![forbid(unsafe_code)]

mod cli;
mod command_options;
mod commands;
mod errors;
mod filtering;
mod input;
#[cfg(test)]
mod ndjson_conformance;
mod rendering;
mod startup;
mod system;

fn main() -> std::process::ExitCode {
    startup::run()
}
