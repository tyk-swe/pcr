// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

mod cli;
mod cli_api;

pub(crate) use cli_api::{
    capture, client, error, net, output, packet, protocol, workflow, workflow_api,
};

fn main() -> std::process::ExitCode {
    cli::run_entrypoint()
}
