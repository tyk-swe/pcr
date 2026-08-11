// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native provider composition for CLI commands; dispatch and rendering remain
//! elsewhere.

mod client;
mod interface;
mod route;
mod target;

pub(crate) use interface::{
    DeferredInterface, validate_interface_selector, validate_live_interface_selector,
};

pub(crate) use route::{prepare_route_request, workflow_exchange_options};

pub(crate) use client::{SystemClient, default_registry_arc, system_client};

pub(crate) use target::parse_workflow_target;
