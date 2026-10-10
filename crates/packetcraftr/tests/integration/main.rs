// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `packetcraftr` integration tests, built as one binary.
//!
//! Each module is one test file. Sharing a binary compiles the helpers and
//! links once, and runs every module in one parallel test pool. Tests that
//! need their own process or crate root stay standalone in `tests/`.

#[path = "../common/mod.rs"]
mod common;

mod adaptive_scheduling_contracts;
mod capture_contracts;
mod connect_clock_contracts;
mod connect_evidence_contracts;
mod discovery_contracts;
mod discovery_matrix;
mod discovery_neighbor_matrix;
mod dns_batch_contracts;
mod dns_cancellation_contracts;
mod dns_wire_contracts;
mod error_classification_contracts;
mod exchange_dns_contracts;
mod exchange_failure_contracts;
mod fuzz_cancellation_contracts;
mod identify_contracts;
mod model_contracts;
mod neighbor_contracts;
mod neighbor_deadline_contracts;
mod policy_contracts;
mod port_selection_matrix;
mod probe_tunnel_contracts;
mod route_contracts;
mod scan_followup_contracts;
mod scan_pipeline_contracts;
mod scanner_corpus_contracts;
mod send_set_contracts;
mod staged_preparation_contracts;
mod traceroute_contracts;
mod traceroute_hosts_contracts;
mod udp_profile_document_contracts;
