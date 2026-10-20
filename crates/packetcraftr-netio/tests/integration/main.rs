// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `packetcraftr-netio` integration tests, built as one binary.
//!
//! Domain modules register the retained suites in one shared parallel test pool.

mod capture;
mod io;
mod resources;
