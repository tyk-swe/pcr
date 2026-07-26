// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native interface enumeration provider.

#![forbid(unsafe_code)]

use packetcraftr_net::Error;
use packetcraftr_net::interface::{Info, Provider as InterfaceProvider};

/// Provider backed by the adapter selected for the current target and feature
/// set. Portable profiles return a typed capability error.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProvider;

impl InterfaceProvider for SystemProvider {
    fn interfaces(&self) -> Result<Vec<Info>, Error> {
        crate::platform::system_interfaces()
    }
}
