// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Windows route and interface adapter backed by IP Helper. `GetBestRoute2`
//! supplies route/source selection and `GetAdaptersAddresses` supplies the
//! portable interface snapshot. Neither API emits neighbor traffic.

#![allow(unsafe_code)]

mod adapter;
mod enumeration;
#[cfg(feature = "native-route")]
mod query;

pub(super) use enumeration::interfaces;
#[cfg(feature = "native-route")]
pub(super) use query::{interface_route, route};
