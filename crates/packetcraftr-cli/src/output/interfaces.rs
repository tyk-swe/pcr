// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use packetcraftr_netio::capture::TimestampType;
use packetcraftr_netio::interface::Info;

use crate::output::network::Interface;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub interfaces: Vec<Interface>,
}

/// Interfaces, each with the timestamp types enumerated for it when they were
/// requested, in index-then-name order with sorted addresses.
impl From<Vec<(Info, Option<Vec<TimestampType>>)>> for Report {
    fn from(interfaces: Vec<(Info, Option<Vec<TimestampType>>)>) -> Self {
        let mut interfaces = interfaces
            .into_iter()
            .map(|(info, timestamp_types)| Interface {
                timestamp_types: timestamp_types
                    .map(|types| types.into_iter().map(Into::into).collect()),
                ..Interface::from(info)
            })
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

impl From<Vec<Info>> for Report {
    fn from(interfaces: Vec<Info>) -> Self {
        interfaces
            .into_iter()
            .map(|info| (info, None))
            .collect::<Vec<_>>()
            .into()
    }
}
