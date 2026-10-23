// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::rendering::multipath::{render_complete, render_event};
use crate::{
    errors::CliError,
    invocation::{Invocation, StreamEncoder},
    output::{self, contract::Format, envelope::Published},
};
use packetcraftr::{
    Client, PacketProviders, TargetProviders, clock::Clock, traceroute::multipath as library,
};

pub(super) fn run<P: PacketProviders + TargetProviders, K: Clock>(
    invocation: &Invocation,
    client: &Client<P, K>,
    request: library::Request,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    request.validate().map_err(CliError::classified)?;
    if format == Format::Json {
        let collector = library::Collector::default();
        let report = client
            .traceroute_multipath(request, collector.clone())
            .map_err(CliError::classified)?;
        let result = collector.finish(report).map_err(CliError::classified)?;
        invocation.check()?;
        return crate::rendering::emit_published(
            invocation,
            output::contract::Command::Traceroute,
            Published::<output::traceroute::multipath::Report>::try_from(result)
                .map_err(CliError::classified)?,
        );
    }
    let text_invocation = invocation.clone();
    let emitter = crate::commands::execution::emitter(invocation, move |event, stream| {
        if format == Format::Ndjson {
            return Ok(stream.emit_published(
                Published::<output::traceroute::multipath::Event>::try_from(event)
                    .map_err(CliError::classified)?,
            )?);
        }
        let mut controlled = text_invocation.clone();
        controlled.output = stream.clone();
        render_event(&controlled, event)
    });
    let report = client
        .traceroute_multipath(request, emitter)
        .map_err(CliError::classified)?;
    invocation.check()?;
    if format == Format::Ndjson {
        Ok(
            stream.complete_published(Published::<output::traceroute::multipath::Event>::from(
                report,
            ))?,
        )
    } else {
        render_complete(invocation, &report)
    }
}
