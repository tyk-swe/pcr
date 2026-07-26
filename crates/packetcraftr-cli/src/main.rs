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

mod arguments;
mod commands;
mod errors;
mod input;
mod rendering;
mod runtime;

#[cfg(test)]
mod tests;

fn main() -> std::process::ExitCode {
    runtime::run_entrypoint()
}
