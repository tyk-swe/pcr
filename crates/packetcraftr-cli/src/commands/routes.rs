// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use self::arguments::Args;
use crate::output::contract::Format;

use crate::output;
use packetcraftr_netio as net;

use crate::errors::CliError;

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
        rendering::route_line,
    )
}
