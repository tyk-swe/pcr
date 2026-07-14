// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

mod arguments;
mod errors;
mod input;
mod rendering;
mod runtime;

#[path = "cli/commands/capture.rs"]
mod capture;
#[path = "cli/commands/dns.rs"]
mod dns;
#[path = "cli/commands/fuzz.rs"]
mod fuzz;
#[path = "cli/commands/interfaces.rs"]
mod interfaces;
#[path = "cli/commands/network.rs"]
mod network;
#[path = "cli/commands/offline.rs"]
mod offline;
#[path = "cli/commands/replay.rs"]
mod replay;
#[path = "cli/commands/scan.rs"]
mod scan;
#[path = "cli/commands/traceroute.rs"]
mod traceroute;

pub(crate) use runtime::run_entrypoint;

#[cfg(test)]
mod tests;
