// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The CLI's one composition root: the only place that names system
//! providers, prepares live operations, and builds the client a command runs
//! on. Dispatch and rendering remain elsewhere.

mod client;
mod exchange;
#[cfg(test)]
pub(crate) mod fixture;
mod interface;
mod preparation;
mod route;

pub(crate) use client::{Client, Runtime, client, runtime};
pub(crate) use interface::{
    InterfaceSelector, interface_route, interfaces, resolve, timestamp_types,
};
pub(crate) use preparation::{
    Prepared, Workflow, placeholder, prepare_live, prepare_plan, prepare_workflow,
};
