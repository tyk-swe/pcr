// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::contract::Format;

use crate::output;
use packetcraftr_netio as net;

use crate::errors::CliError;
use crate::rendering::optional_display;

pub(crate) const AFTER_LONG_HELP: &str = r"Examples:
  packetcraftr routes
  packetcraftr routes --all
  packetcraftr --output json routes";

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

impl super::Spec for Args {
    const FORMATS: &'static [crate::output::contract::Format] = &[
        crate::output::contract::Format::Text,
        crate::output::contract::Format::Json,
    ];
    const CANCELLATION: bool = false;

    fn run(
        self,
        format: Format,
        _stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(arguments: Args, format: Format) -> Result<(), CliError> {
    let interfaces = crate::system::interfaces(None)?;
    let mut routes = Vec::new();
    for interface in interfaces
        .into_iter()
        .filter(|interface| arguments.includes(interface))
    {
        if let Some(route) = crate::system::interface_route(&interface.id)? {
            routes.push(route);
        }
    }
    routes.sort_by_key(|route| (route.interface.index, route.interface.name.clone()));
    routes.dedup_by(|left, right| left.interface == right.interface);
    let result = output::routes::Report::from(routes);
    crate::rendering::render_aggregate_rows(
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
