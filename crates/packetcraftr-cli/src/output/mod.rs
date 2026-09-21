// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! CLI machine output. Domain values stay with their owning crate; these
//! representations handle hex encoding, timestamps, flattened reports, and
//! the versioned envelope. The stream encoder owns ordering and termination.
//! Every output-v6 NDJSON record declares its kind in the envelope's `event`.

pub mod build;
pub mod capture;
pub mod contract;
pub mod dissect;
pub mod dns;
pub mod dns_analysis;
pub mod envelope;
pub mod exchange;
pub mod expert;
pub mod export;
pub mod follow;
pub mod forwarding;
pub mod fragment;
pub mod frame;
pub mod fuzz;
pub mod hex;
pub mod http;
pub mod interfaces;
pub mod merge;
pub mod network;
pub mod plan;
pub mod projection;
pub mod protocols;
pub mod provenance;
pub mod read;
pub mod reassembly;
pub mod replay;
pub mod resources;
pub mod rewrite;
pub mod routes;
pub mod scan;
pub mod scan_connect;
pub mod send;
pub mod stats;
pub mod stream;
pub mod tls;
pub mod traceroute;
