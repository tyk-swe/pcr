// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;

use std::sync::Arc;

use packetcraftr::output;

use self::arguments::Args;
use super::super::rendering::{emit_aggregate, optional_display, write_stdout_line};
use super::super::system::{client, prepare_route};
use super::registry;
use packetcraftr::BoundaryError;

pub(super) fn run(arguments: Args, format: output::contract::Format) -> Result<(), BoundaryError> {
    let Args { route, policy } = arguments;
    let registry = registry()?;
    let request = prepare_route(route, policy.into_policy(), &registry)?;
    let client = client(Arc::clone(&registry), request.policy);
    let route = client
        .plan(&request.packet, request.destination, &request.options)
        .map_err(BoundaryError::from_error)?;
    let result = output::plan::Result { plan: route.into() };
    match format {
        output::contract::Format::Text => render_text(&result.plan),
        output::contract::Format::Json => {
            emit_aggregate(output::contract::Command::Plan, result, Vec::new())
        }
        _ => unreachable!("plan format is checked before command dispatch"),
    }
}

fn render_text(route: &output::network::Plan) -> Result<(), BoundaryError> {
    write_stdout_line(format_args!(
        "interface={} index={} mode={:?} mtu={} link_type={}",
        route.decision.interface.name,
        route.decision.interface.index,
        route.mode,
        route.decision.mtu,
        route.decision.link_type
    ))?;
    write_stdout_line(format_args!(
        "lookup_destination={} final_destination={} source={} next_hop={} destination_mac={}",
        optional_display(route.lookup_destination),
        optional_display(route.final_destination),
        optional_display(route.packet_source),
        optional_display(route.decision.next_hop),
        route
            .destination_mac
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unresolved".to_owned())
    ))
}
