// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Concrete adapters that execute workflow contracts through the audited
//! client and the native transmission providers.
//!
//! [`packetcraftr_workflow`] stays free of these adapters so its engines remain
//! testable through controlled executors and authorizers. Policy-only
//! authorizers stay with the engines they gate; everything here needs a live
//! [`packetcraftr_client::Client`] or a native provider.

#![forbid(unsafe_code)]

pub mod dns;
pub mod fuzz;
pub mod replay;
pub mod scan;
pub mod traceroute;
