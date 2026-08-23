// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Linux route and interface adapter backed by route netlink.

#![forbid(unsafe_code)]

mod query;
mod worker;

pub(super) use query::{interface_route, interfaces, route};
pub(super) use worker::os_error;
