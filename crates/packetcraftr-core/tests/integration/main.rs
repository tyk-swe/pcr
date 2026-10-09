// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `packetcraftr-core` integration tests, built as one binary.
//!
//! Each module is one test file. Sharing a binary compiles the helpers and
//! links once, and runs every module in one parallel test pool. Tests that
//! need their own process or crate root stay standalone in `tests/`.

#[path = "../common/mod.rs"]
mod common;

mod application_codec_contracts;
mod capture_compression_contracts;
mod capture_file_edge_contracts;
mod capture_file_fidelity_contracts;
mod capture_file_rewrite_contracts;
mod capture_limit_contracts;
mod capture_merge_contracts;
mod conversation_contracts;
mod core_model_contracts;
mod dependency_export_contracts;
mod dhcp_contracts;
mod dns_analysis_contracts;
mod dns_construction_contracts;
mod dns_multicast_contracts;
mod dns_record_contracts;
mod document_limit_contracts;
mod error_classification_contracts;
mod etherip_tunnel_contracts;
mod field_catalog_contracts;
mod field_edit_contracts;
mod filter_contracts;
mod forwarding_verification_contracts;
mod fragment_transform_contracts;
mod fuzz_contracts;
mod fuzz_engine_contracts;
mod fuzz_roundtrip_contracts;
mod gtpu_tunnel_contracts;
mod header_rewrite_contracts;
mod http2_analysis_contracts;
mod http2_limit_contracts;
mod http2_state_matrix;
mod http2_wire_conformance;
mod http_analysis_contracts;
mod http_framing_contracts;
mod invocation_deadline_contracts;
mod ip_pipeline_budget_contracts;
mod ip_pipeline_tcp_contracts;
mod ip_reassembly_contracts;
mod link_control_contracts;
mod matcher_contracts;
mod ntp_contracts;
mod packet_recipe_contracts;
mod perf_capture_io_contracts;
mod perf_filter_projection_contracts;
mod perf_provenance_contracts;
mod pipeline_limit_contracts;
mod protocol_builtin_wire_contracts;
mod protocol_end_to_end_contracts;
mod rewrite_rules_contracts;
mod runtime_document_contracts;
mod runtime_reflection_contracts;
mod runtime_registry_contracts;
mod semantic_contracts;
mod service_identification_contracts;
mod syslog_contracts;
mod tcp_option_contracts;
mod tcp_reassembly_edge_contracts;
mod tftp_contracts;
mod tls_construction_contracts;
mod tls_dissection_contracts;
mod tls_session_assembly_contracts;
mod tls_session_gap_contracts;
mod tls_session_handshake_contracts;
mod tls_session_limit_contracts;
mod tls_session_record_contracts;
