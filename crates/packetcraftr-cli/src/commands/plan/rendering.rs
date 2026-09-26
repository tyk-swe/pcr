// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `plan`'s text output.

use crate::errors::CliError;
use crate::output;
use crate::rendering::{optional_display, write_stdout_line};

pub(super) fn render_text(route: &output::network::Plan) -> Result<(), CliError> {
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
