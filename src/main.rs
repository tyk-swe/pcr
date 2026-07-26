// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Thin launcher for the `packetcraftr` executable. Every argument, command,
//! and rendering decision lives in `packetcraftr-cli`.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    packetcraftr_cli::run_entrypoint()
}
