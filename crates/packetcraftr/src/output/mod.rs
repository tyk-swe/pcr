// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Versioned structured-output contracts.
//!
//! The v1 vocabulary is deliberately scoped by responsibility and command. Types
//! in this module describe the serialized CLI contract; they are not aliases for
//! workflow results intended to evolve independently.

pub mod build;
pub mod capture;
pub mod contract;
pub mod dissect;
pub mod dns;
pub mod envelope;
pub mod exchange;
pub mod expert;
pub mod follow;
mod frame;
pub mod fuzz;
mod hex;
pub mod interfaces;
mod network;
pub mod plan;
pub mod protocols;
pub mod read;
pub mod replay;
pub mod routes;
pub mod scan;
pub mod send;
pub mod stats;
pub mod traceroute;

#[cfg(test)]
mod tests;
