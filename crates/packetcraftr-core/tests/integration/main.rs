// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `packetcraftr-core` integration tests, built as one binary.
//!
//! Domain modules register the retained suites in one shared parallel test pool.

#[path = "../common.rs"]
mod common;

mod analysis;
mod capture_file;
mod document;
mod security;
