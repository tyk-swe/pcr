// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;

use crate::output::contract::AggregateFormat;

use std::sync::Arc;

use crate::output;

use self::arguments::Args;
use crate::errors::CliError;
use crate::rendering::{emit_aggregate, optional_display, write_stdout_line};
use crate::system::{client, prepare_route};

impl super::Spec for Args {
    type Format = crate::output::contract::AggregateFormat;
    const CANCELLATION: bool = false;

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        self.policy.resources(settings);
    }

    fn run(
        self,
        format: Self::Format,
        _stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(arguments: Args, format: AggregateFormat) -> Result<(), CliError> {
    let Args { route, policy } = arguments;
    let registry = packetcraftr_core::protocol::builtin::registry();
    let request = prepare_route(route, policy.into_policy(), &registry)?;
    let client = client(Arc::clone(&registry), request.policy);
    let route = client
        .plan(&request.packet, request.destination, &request.options)
        .map_err(CliError::classified)?;
    let result = output::plan::Report { plan: route.into() };
    match format {
        AggregateFormat::Text => render_text(&result.plan),
        AggregateFormat::Json => {
            emit_aggregate(output::contract::Command::Plan, result, Vec::new())
        }
    }
}

fn render_text(route: &output::network::Plan) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "interface={} index={} mode={} mtu={} link_type={}",
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
