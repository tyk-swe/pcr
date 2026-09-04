// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::netio::{interface::Provider as _, route::Provider as _};
use packetcraftr::{netio as net, output};

use super::format::AggregateFormat;
use crate::errors::CliError;
use crate::rendering::optional_display;

pub(super) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr routes
  packetcraftr routes --all
  packetcraftr --output json routes"#;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Report every enumerated interface, including ones that are not up.
    #[arg(long)]
    pub(crate) all: bool,
}

pub(super) fn run(arguments: Args, format: output::contract::Format) -> Result<(), CliError> {
    let format = AggregateFormat::narrow(output::contract::Command::Routes, format)?;
    let interfaces = net::interface::SystemProvider
        .interfaces()
        .map_err(CliError::classified)?;
    let provider = net::route::SystemProvider;
    let mut routes = Vec::new();
    for interface in interfaces
        .into_iter()
        .filter(|interface| arguments.all || interface.flags.up)
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
