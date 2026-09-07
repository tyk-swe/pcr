// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! CLI machine output. Domain values stay with their owning crate; these
//! representations handle hex encoding, timestamps, flattened reports, and
//! the versioned envelope. The stream encoder owns ordering and termination.
//! Every output-v2 NDJSON record declares its kind in the envelope's `event`.

pub mod build;
pub mod capture;
pub mod contract;
pub mod dissect;
pub mod dns;
pub mod envelope;
pub mod exchange;
pub mod expert;
pub mod follow;
pub mod frame;
pub mod fuzz;
mod hex;
pub mod interfaces;
pub mod network;
pub mod plan;
pub mod protocols;
pub mod read;
pub mod reassembly;
pub mod replay;
pub mod routes;
pub mod scan;
pub mod send;
pub mod stats;
pub mod stream;
pub mod tls;
pub mod traceroute;
