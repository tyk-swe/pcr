// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::net::{interface::Provider as _, route::Provider as _};
use packetcraftr::{net, output};

use super::super::errors::CliError;
use super::super::rendering::{emit_json, write_stdout_line};

pub(crate) fn run_routes(output: output::contract::Format) -> Result<(), CliError> {
    let interfaces = net::interface::SystemProvider
        .interfaces()
        .map_err(CliError::classified)?;
    let provider = net::route::SystemProvider;
    let mut routes = Vec::new();
    for interface in interfaces
        .into_iter()
        .filter(|interface| interface.flags.up)
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
    let result = output::routes::Result {
        routes: routes.into_iter().map(Into::into).collect(),
    };
    match output {
        output::contract::Format::Text => {
            for route in result.routes {
                write_stdout_line(format_args!(
                    "{} (index {}): source={} mtu={} capability={:?} link_type={}",
                    route.interface.name,
                    route.interface.index,
                    optional_display(route.selected_address.or(route.preferred_source)),
                    route.mtu,
                    route.capability,
                    route.link_type
                ))?;
            }
            Ok(())
        }
        output::contract::Format::Json => emit_json(&output::envelope::Aggregate::success(
            output::contract::Command::Routes,
            result,
            Vec::new(),
        )),
        _ => Err(CliError::classified(
            output::contract::Error::UnsupportedFormat {
                command: output::contract::Command::Routes,
                format: output,
            },
        )),
    }
}

fn optional_display<T: std::fmt::Display>(value: Option<T>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_owned())
}
