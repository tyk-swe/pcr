// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `packetcraftr-core` integration tests, built as one binary.
//!
//! Each module is one test file. Sharing a binary compiles the helpers and
//! links once, and runs every module in one parallel test pool.

#[path = "../common/mod.rs"]
mod common;

mod analysis_control_contracts;
mod analysis_provenance_contracts;
mod capture_compression_contracts;
mod capture_file_edge_contracts;
mod document_limit_contracts;
mod security_scan_contracts;
mod tls_session_limit_contracts;
