// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The `packetcraftr` command-line interface.
//!
//! This crate is the only PacketcraftR target that renders to a terminal. It
//! parses arguments, composes the library domains re-exported by the
//! `packetcraftr` facade, and serializes every result through
//! `packetcraftr::output` so the JSON contract stays independent of the
//! terminal presentation.

#![forbid(unsafe_code)]

mod capture_output;
mod cli;
mod command_options;
mod commands;
mod errors;
mod filtering;
mod input;
mod rendering;
mod startup;
mod system;

fn main() -> std::process::ExitCode {
    startup::run_entrypoint()
}
