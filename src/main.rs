// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

mod cli;

fn main() -> std::process::ExitCode {
    cli::run_entrypoint()
}
