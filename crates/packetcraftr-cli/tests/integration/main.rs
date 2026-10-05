// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `packetcraftr-cli` integration tests, built as one binary.
//!
//! Each module is one test file. Sharing a binary compiles the helpers and
//! links once, and runs every module in one parallel test pool. Tests that
//! need their own process or crate root stay standalone in `tests/`.

#[path = "../common/capture.rs"]
mod capture_support;
#[path = "../common/mod.rs"]
mod common;
#[path = "../common/process.rs"]
mod process_support;
#[path = "../common/stats_report.rs"]
mod stats_report;
#[path = "../common/tls_capture.rs"]
mod tls_capture;

mod aggregate_schema_conformance;
mod cancellation_contracts;
mod capability_contracts;
mod capture_argument_contracts;
mod capture_merge_contracts;
mod capture_stdin_contracts;
mod compressed_capture_contracts;
mod connect_scan_contracts;
mod construction_workflow_contracts;
mod decode_as_contracts;
mod dependency_export_contracts;
mod dissect_input_contracts;
mod dns_output_contracts;
mod dns_read_contracts;
mod dns_tcp_direct_contracts;
mod documentation_failure_contracts;
mod field_edit_contracts;
mod field_projection_contracts;
mod forwarding_verification_contracts;
mod frame_selection_contracts;
mod header_rewrite_contracts;
mod http2_contracts;
mod http_contracts;
mod ndjson_conformance;
mod normalized_capture_contracts;
mod offline_fuzz_contracts;
mod offline_workflow_contracts;
mod packet_set_contracts;
mod process_contracts;
mod published_schema_conformance;
mod recipe_payload_contracts;
mod resource_diagnostic_contracts;
mod scan_payload_contracts;
mod scanner_corpus_conformance;
mod stdout_failure_contracts;
mod target_planning_contracts;
mod tls_workflow_contracts;
mod udp_profile_contracts;
