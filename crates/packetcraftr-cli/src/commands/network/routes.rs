// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::contract::Format;

use crate::output;
use packetcraftr_netio as net;

use crate::errors::CliError;
use crate::rendering::optional_display;

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

impl crate::commands::Spec for Args {
    const FORMATS: &'static [crate::output::contract::Format] = &[
        crate::output::contract::Format::Text,
        crate::output::contract::Format::Json,
    ];
    const CANCELLATION: bool = false;

    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        let format = invocation.format;
        run(invocation, self, format).map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    invocation: &crate::invocation::Invocation,
    arguments: Args,
    format: Format,
) -> Result<(), CliError> {
    let interfaces = crate::system::interfaces(invocation, None)?;
    let mut routes = Vec::new();
    for interface in interfaces
        .into_iter()
        .filter(|interface| arguments.includes(interface))
    {
        if let Some(route) = crate::system::interface_route(invocation, &interface.id)? {
            routes.push(route);
        }
    }
    routes.sort_by_key(|route| (route.interface.index, route.interface.name.clone()));
    routes.dedup_by(|left, right| left.interface == right.interface);
    let result = output::routes::Report::from(routes);
    crate::rendering::render_aggregate_rows(
        invocation,
        output::contract::Command::Routes,
        format,
        &result,
        &result.routes,
        route_line,
    )
}

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
