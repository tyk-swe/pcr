// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `packetcraftr-cli` integration tests, built as one binary.
//!
//! Each module is one test file. Sharing a binary compiles the helpers and
//! links once, and runs every module in one parallel test pool.

#[path = "../common/capture.rs"]
mod capture_support;
#[path = "../common/mod.rs"]
mod common;
#[path = "../common/process.rs"]
mod process_support;

mod capture_stdin_contracts;
mod connect_scan_contracts;
mod field_edit_contracts;
mod forwarding_verification_contracts;
mod grouped_cli_contracts;
mod http2_contracts;
mod offline_fuzz_contracts;
mod offline_workflow_contracts;
mod packet_set_contracts;
mod published_schema_conformance;
mod scan_measurement_contracts;
mod target_planning_contracts;
mod tls_workflow_contracts;

mod security_contracts;
