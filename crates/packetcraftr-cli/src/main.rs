// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Process entry point for the [`packetcraftr_cli`] application.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    packetcraftr_cli::main()
}
