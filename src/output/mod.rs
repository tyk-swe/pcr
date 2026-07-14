// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Versioned structured-output contracts.
//!
//! The v1 vocabulary is deliberately scoped by responsibility and command. Types
//! in this module describe the serialized CLI contract; they are not aliases for
//! workflow results intended to evolve independently.

#![forbid(unsafe_code)]

pub mod build;
pub mod capture;
mod common;
pub mod contract;
pub mod dissect;
pub mod dns;
pub mod envelope;
pub mod frame;
pub mod fuzz;
pub mod network;
pub mod replay;
pub mod scan;
pub mod traceroute;

#[cfg(test)]
mod tests;
