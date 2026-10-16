// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `packetcraftr` integration tests, built as one binary.
//!
//! Each module is one test file. Sharing a binary compiles the helpers and
//! links once, and runs every module in one parallel test pool.

#[path = "../common/mod.rs"]
mod common;

mod dns_cancellation_contracts;
mod policy_contracts;

mod scan_control_contracts;
mod scanner_fixture;

mod transmit_only_contracts;

mod scan_measurement_contracts;
mod scan_serial_retention_contracts;
