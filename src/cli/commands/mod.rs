// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Command-specific CLI adapters.

mod capture;
mod dns;
mod fuzz;
mod interfaces;
mod network;
mod offline;
mod replay;
mod scan;
mod traceroute;

pub(super) use capture::{run_capture, run_exchange};
pub(super) use dns::run_dns;
pub(super) use fuzz::run_fuzz;
pub(super) use interfaces::run_interfaces;
pub(super) use network::{run_plan, run_routes, run_send};
pub(super) use offline::{run_build, run_dissect, run_read};
pub(super) use replay::run_replay;
pub(super) use scan::run_scan;
pub(super) use traceroute::run_traceroute;

#[cfg(test)]
pub(super) use capture::{CaptureBudget, drive_capture};
#[cfg(test)]
pub(super) use dns::dns_cli_error;
#[cfg(test)]
pub(super) use fuzz::fuzz_cli_error;
#[cfg(test)]
pub(super) use network::send_capture_link_type;
#[cfg(test)]
pub(super) use replay::{replay_cli_error, write_replay_capture_evidence};
#[cfg(test)]
pub(super) use scan::scan_cli_error;
#[cfg(test)]
pub(super) use traceroute::traceroute_cli_error;
