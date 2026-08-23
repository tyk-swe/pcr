// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native provider composition for CLI commands; dispatch and rendering remain
//! elsewhere.

mod client;
pub(crate) mod exchange;
mod executor;
mod interface;
mod route;

pub(crate) use client::{Client, Exchange, client};
pub(crate) use executor::Executor;
pub(crate) use interface::{resolve, validate_selector};
pub(crate) use route::prepare_route;
