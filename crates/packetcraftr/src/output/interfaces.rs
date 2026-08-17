// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Output contract for the `interfaces` command.

use serde::Serialize;

use packetcraftr_netio::interface::Info;

use crate::output::network::Interface;

/// Aggregate result of `interfaces`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Result {
    pub interfaces: Vec<Interface>,
}

impl Result {
    pub fn new(interfaces: Vec<Info>) -> Self {
        let mut interfaces = interfaces
            .into_iter()
            .map(Interface::from)
            .collect::<Vec<_>>();
        for interface in &mut interfaces {
            interface.addresses.sort();
        }
        interfaces.sort_by(|left, right| {
            (left.index, left.name.as_str()).cmp(&(right.index, right.name.as_str()))
        });
        Self { interfaces }
    }
}
