// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(in crate::commands) mod output;

use packetcraftr_netio as net;

use crate::errors::CliError;
use crate::terminal::render_optional;

pub(crate) const AFTER_LONG_HELP: &str = r"Examples:
  packetcraftr network routes
  packetcraftr network routes --all
  packetcraftr --output json network routes";

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

use crate::output::contract::PublishedType;

impl crate::commands::Spec for Args {
    const PUBLISHED: &'static [PublishedType] = &[PublishedType {
        definition: "routesSuccess",
        command: "routes",
        rust_types: &["crate::commands::network::routes::output::Report"],
        events: &[],
        example: "examples/documents/output-routes-success.json",
    }];
    const FORMATS: &'static [crate::output::contract::Format] = crate::output::contract::TEXT_JSON;
    const CANCELLATION: bool = false;

    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        run(invocation, self).map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    invocation: &crate::invocation::Invocation,
    arguments: Args,
) -> Result<(), CliError> {
    let format = invocation.format;
    let routes = collect_routes(
        &arguments,
        || crate::system::interfaces(invocation, None),
        |interfaces| crate::system::interface_routes(invocation, interfaces),
    )?;
    let result = output::Report::from(routes);
    crate::commands::aggregate::render_aggregate_rows(
        invocation,
        crate::output::contract::Command::Routes,
        format,
        &result,
        &result.routes,
        route_line,
    )
}

fn collect_routes(
    arguments: &Args,
    survey: impl FnOnce() -> Result<Vec<net::interface::Info>, CliError>,
    route: impl FnOnce(Vec<net::interface::Info>) -> Result<Vec<net::route::Decision>, CliError>,
) -> Result<Vec<net::route::Decision>, CliError> {
    let interfaces = survey()?
        .into_iter()
        .filter(|interface| arguments.includes(interface))
        .collect();
    let mut routes = route(interfaces)?;
    routes.sort_by(|left, right| {
        (left.interface.index, &left.interface.name)
            .cmp(&(right.interface.index, &right.interface.name))
    });
    routes.dedup_by(|left, right| left.interface == right.interface);
    Ok(routes)
}

fn route_line(route: &crate::output::network::Decision) -> String {
    format!(
        "{} (index {}): source={} mtu={} capability={} link_type={}",
        route.interface.name,
        route.interface.index,
        render_optional(route.selected_source.or(route.preferred_source), |value| {
            value.to_string()
        }),
        route.mtu,
        route.capability,
        route.link_type
    )
}

#[cfg(all(test, target_os = "linux", feature = "native-route"))]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::time::Duration;

    fn interface(index: u32, up: bool) -> net::interface::Info {
        net::interface::Info {
            id: net::interface::Id {
                name: format!("if{index}"),
                index,
            },
            description: None,
            mac_address: None,
            addresses: Vec::new(),
            flags: net::interface::Flags {
                up,
                ..Default::default()
            },
            mtu: Some(1500),
            capability: net::link::Capability::Layer3,
            link_type: packetcraftr_core::frame::LinkType::RAW,
        }
    }

    #[test]
    fn route_listing_filters_one_ordered_survey() {
        for size in [1, 1000] {
            for all in [false, true] {
                let surveys = Cell::new(0);
                let conversions = Cell::new(0);
                let interfaces = (1..=size)
                    .rev()
                    .map(|index| interface(index, index % 2 == 1))
                    .collect::<Vec<_>>();
                let routes = collect_routes(
                    &Args { all },
                    || {
                        surveys.set(surveys.get() + 1);
                        Ok(interfaces)
                    },
                    |interfaces| {
                        conversions.set(conversions.get() + 1);
                        net::route::SystemProvider
                            .lookup_interface_snapshot(
                                interfaces,
                                &packetcraftr_core::budget::Deadline::new(Duration::from_secs(5)),
                            )
                            .map_err(CliError::classified)
                    },
                )
                .unwrap();
                let expected = (1..=size)
                    .filter(|index| all || index % 2 == 1)
                    .collect::<Vec<_>>();
                assert_eq!(
                    routes
                        .iter()
                        .map(|route| route.interface.index)
                        .collect::<Vec<_>>(),
                    expected
                );
                assert!(routes.iter().all(
                    |route| route.selected_source.is_none() && route.preferred_source.is_none()
                ));
                assert_eq!(surveys.get(), 1);
                assert_eq!(conversions.get(), 1);
            }
        }
    }
}
