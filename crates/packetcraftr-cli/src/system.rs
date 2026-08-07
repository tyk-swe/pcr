// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native-system composition used by CLI commands.
//!
//! This module binds the facade's provider traits to system route, neighbor,
//! capture, and transmission adapters. It does not own command dispatch or
//! output rendering.

mod client;
mod interface;
mod route;
mod target;

pub(crate) use interface::{DeferredInterface, validate_interface_selector};

pub(crate) use route::{prepare_route_request, workflow_exchange_options};

pub(crate) use client::{SystemClient, default_registry_arc, system_client};

pub(crate) use target::parse_workflow_target;
