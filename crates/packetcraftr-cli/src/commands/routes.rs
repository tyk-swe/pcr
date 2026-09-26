// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use self::arguments::Args;
use crate::output::contract::AggregateFormat;

use crate::output;
use packetcraftr_netio as net;
use packetcraftr_netio::interface::Provider as _;
use packetcraftr_netio::route::Provider as _;

use crate::errors::CliError;

impl Args {
    fn includes(&self, interface: &net::interface::Info) -> bool {
        (self.all || interface.flags.up) && interface.mtu.is_some_and(|mtu| mtu != 0)
    }
}

impl super::Spec for Args {
    type Format = crate::output::contract::AggregateFormat;
    const CANCELLATION: bool = false;

    fn run(
        self,
        format: Self::Format,
        _stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(arguments: Args, format: AggregateFormat) -> Result<(), CliError> {
    let interfaces = net::interface::SystemProvider
        .interfaces(&crate::invocation::passive_lookup())
        .map_err(CliError::classified)?;
    let provider = net::route::SystemProvider;
    let mut routes = Vec::new();
    for interface in interfaces
        .into_iter()
        .filter(|interface| arguments.includes(interface))
    {
        let route = provider
            .lookup_interface(&interface.id, &crate::invocation::passive_lookup())
            .map_err(CliError::classified)?;
        if let Some(route) = route {
            routes.push(route);
        }
    }
    routes.sort_by_key(|route| (route.interface.index, route.interface.name.clone()));
    routes.dedup_by(|left, right| left.interface == right.interface);
    let result = output::routes::Report::from(routes);
    super::render_aggregate_rows(
        output::contract::Command::Routes,
        format,
        &result,
        &result.routes,
        rendering::route_line,
    )
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn route_listing_requires_a_usable_mtu_even_when_including_down_interfaces() {
        let mut interface = net::interface::Info {
            id: net::interface::Id {
                name: "fixture0".to_owned(),
                index: 7,
            },
            description: None,
            mac_address: None,
            addresses: Vec::new(),
            flags: net::interface::Flags::default(),
            mtu: None,
            capability: net::link::Capability::Layer3,
            link_type: packetcraftr_core::frame::LinkType::RAW,
        };
        for up in [false, true] {
            interface.flags.up = up;
            for mtu in [None, Some(0)] {
                interface.mtu = mtu;
                assert!(!Args { all: false }.includes(&interface));
                assert!(!Args { all: true }.includes(&interface));
            }
            interface.mtu = Some(1_500);
            assert_eq!(Args { all: false }.includes(&interface), up);
            assert!(Args { all: true }.includes(&interface));
        }
    }
}
