// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private implementation vocabulary for versioned output contracts.

#![forbid(unsafe_code)]

pub(super) mod build;
pub(super) mod capture;
mod common;
pub(super) mod contract;
pub(super) mod dissect;
pub(super) mod dns;
pub(super) mod envelope;
pub(super) mod frame;
pub(super) mod fuzz;
pub(super) mod network;
pub(super) mod replay;
pub(super) mod scan;
pub(super) mod traceroute;

#[cfg(test)]
mod tests;
