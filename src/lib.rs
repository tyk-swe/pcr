// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

#![warn(unreachable_pub)]

mod app;
mod cli;
mod domain;
mod engine;
mod network;
mod output;
mod rules;
mod tools;
mod util;

pub use app::{run_cli, run_cli_entry};
