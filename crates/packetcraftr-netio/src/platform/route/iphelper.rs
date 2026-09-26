// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Windows route and interface adapter backed by IP Helper. `GetBestRoute2`
//! supplies route/source selection and `GetAdaptersAddresses` supplies the
//! portable interface snapshot. Neither API emits neighbor traffic.

mod adapter;
mod enumeration;
mod query;

use crate::interface;

pub(in crate::platform) use query::{interface_route, route};

pub(in crate::platform) fn interfaces() -> Result<Vec<interface::Info>, interface::Error> {
    enumeration::interfaces().map_err(interface::Error::native)
}
