// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native provider composition for CLI commands; dispatch and rendering remain
//! elsewhere.

mod client;
pub(crate) mod exchange;
mod interface;
mod route;

pub(crate) use interface::{InterfaceSelector, resolve};

pub(crate) use route::prepare_route;

pub(crate) use client::{Client, Exchange, client};
