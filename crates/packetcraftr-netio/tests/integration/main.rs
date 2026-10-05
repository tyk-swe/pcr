// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `packetcraftr-netio` integration tests, built as one binary.
//!
//! Each module is one test file. Sharing a binary compiles the helpers and
//! links once, and runs every module in one parallel test pool. Tests that
//! need their own process or crate root stay standalone in `tests/`.

#[path = "../common/mod.rs"]
mod common;

mod capture_group_contracts;
mod deadline_contracts;
mod error_contracts;
mod model_contracts;
mod transmit_contracts;
