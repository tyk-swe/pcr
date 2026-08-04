// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr::output;

use super::super::arguments::PlanArgs;
use super::super::errors::CliError;
use super::super::rendering::{emit_json, write_stdout_line};
use super::super::runtime::{default_registry_arc, prepare_route_request, system_client};

pub(crate) fn run_plan(
    arguments: PlanArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    let PlanArgs { route, policy } = arguments;
    let registry = default_registry_arc()?;
    let request = prepare_route_request(route, policy.into_policy(), &registry)?;
    let client = system_client(Arc::clone(&registry), request.policy);
    let route = client
        .plan(&request.packet, request.destination, &request.options)
        .map_err(CliError::classified)?;
    let result = output::plan::Result {
        route: route.into(),
    };
    match output {
        output::contract::Format::Text => render_planned_route(&result.route),
        output::contract::Format::Json => emit_json(&output::envelope::Aggregate::success(
            output::contract::Command::Plan,
            result,
            Vec::new(),
        )),
        _ => Err(CliError::classified(
            output::contract::Error::UnsupportedFormat {
                command: output::contract::Command::Plan,
                format: output,
            },
        )),
    }
}

fn render_planned_route(route: &output::plan::Plan) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "interface={} index={} mode={:?} mtu={} link_type={}",
        route.route.interface.name,
        route.route.interface.index,
        route.mode,
        route.route.mtu,
        route.route.link_type
    ))?;
    write_stdout_line(format_args!(
        "lookup_destination={} final_destination={} source={} next_hop={} destination_mac={}",
        optional_display(route.lookup_destination),
        optional_display(route.final_destination),
        optional_display(route.packet_source),
        optional_display(route.route.next_hop),
        route
            .destination_mac
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unresolved".to_owned())
    ))
}

fn optional_display<T: std::fmt::Display>(value: Option<T>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_owned())
}
