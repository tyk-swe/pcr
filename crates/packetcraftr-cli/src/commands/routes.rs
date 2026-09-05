// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::output::contract::Format;

use packetcraftr::netio::{interface::Provider as _, route::Provider as _};
use packetcraftr::{netio as net, output};

use crate::errors::CliError;
use crate::rendering::optional_display;

pub(super) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr routes
  packetcraftr routes --all
  packetcraftr --output json routes"#;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Report all interfaces with a usable MTU, including ones that are not up.
    #[arg(long)]
    pub(crate) all: bool,
}

impl Args {
    fn includes(&self, interface: &net::interface::Info) -> bool {
        (self.all || interface.flags.up) && interface.mtu.is_some_and(|mtu| mtu != 0)
    }
}

pub(super) fn run(arguments: Args, format: Format) -> Result<(), CliError> {
    let interfaces = net::interface::SystemProvider
        .interfaces()
        .map_err(CliError::classified)?;
    let provider = net::route::SystemProvider;
    let mut routes = Vec::new();
    for interface in interfaces
        .into_iter()
        .filter(|interface| arguments.includes(interface))
    {
        let route = provider.lookup_interface(&interface.id).map_err(|source| {
            CliError::from_classification(
                provider.classify_error(&source),
                source.to_string(),
                Vec::new(),
            )
        })?;
        if let Some(route) = route {
            routes.push(route);
        }
    }
    routes.sort_by_key(|route| (route.interface.index, route.interface.name.clone()));
    routes.dedup_by(|left, right| left.interface == right.interface);
    let result = output::routes::Report {
        routes: routes.into_iter().map(Into::into).collect(),
    };
    super::render_aggregate_rows(
        output::contract::Command::Routes,
        format,
        &result,
        &result.routes,
        route_line,
    )
}

/// One text row per route.
fn route_line(route: &output::network::Decision) -> String {
    format!(
        "{} (index {}): source={} mtu={} capability={} link_type={}",
        route.interface.name,
        route.interface.index,
        optional_display(route.selected_source.or(route.preferred_source)),
        route.mtu,
        route.capability,
        route.link_type
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

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
            link_type: packetcraftr::core::frame::LinkType::RAW,
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
