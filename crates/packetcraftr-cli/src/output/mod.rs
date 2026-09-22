// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! CLI machine output: hex, timestamps, reports, and versioned envelopes. The
//! stream encoder owns ordering/termination; each NDJSON envelope names its
//! `event`.

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
pub mod frame;
pub mod fuzz;
pub mod hex;
pub mod http;
pub mod interfaces;
pub mod network;
pub mod plan;
pub mod protocols;
pub mod provenance;
pub mod read;
pub mod reassembly;
pub mod replay;
pub mod resources;
pub mod rewrite;
pub mod routes;
pub mod scan;
pub mod send;
pub mod stats;
pub mod stream;
pub mod tls;
pub mod traceroute;
pub mod workflow;

pub mod forwarding;

pub mod fragment;

pub mod merge;

pub mod projection;

pub mod scan_connect;
