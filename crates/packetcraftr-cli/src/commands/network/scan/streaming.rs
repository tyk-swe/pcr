// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Scan and follow-up events in the versioned streaming output contract.

use packetcraftr::scan::followup;

use crate::{errors::CliError, output, rendering::StreamEncoder};

pub(super) fn emit_event(event: followup::Event, stream: &StreamEncoder) -> Result<(), CliError> {
    match event {
        followup::Event::Scan(event) => {
            let published = output::envelope::Published::<output::scan::Event>::try_from(event)
                .map_err(CliError::classified)?;
            Ok(stream.emit_published(published)?)
        }
        followup::Event::Trace(packetcraftr::traceroute::hosts::Event::Diagnostic(diagnostic)) => {
            Ok(stream.emit_published(output::envelope::Published::new(
                output::scan::Event::Diagnostic {},
                vec![diagnostic],
            ))?)
        }
        followup::Event::Trace(event) => {
            let record = output::traceroute::hosts::Event::publish(event)
                .map_err(CliError::classified)?
                .expect("only diagnostics have no trace record");
            Ok(stream.emit_data(record, Vec::new())?)
        }
    }
}

pub(super) fn emit_complete(
    streamed: super::raw::Streamed,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let super::raw::Streamed {
        mut report,
        endpoints,
        plan,
        reverse_dns,
        traceroute,
    } = streamed;
    for endpoint in endpoints {
        stream.emit_published(output::envelope::Published::<output::scan::Event>::from(
            endpoint,
        ))?;
    }
    emit_hosts(std::mem::take(&mut report.hosts), reverse_dns, stream)?;
    Ok(
        stream.complete_published(output::envelope::Published::<output::scan::Event>::from((
            report, plan, traceroute,
        )))?,
    )
}

/// One `host` record per target after the last probe, before `complete`.
pub(super) fn emit_hosts(
    hosts: Vec<packetcraftr::scan::discovery::Host>,
    reverse_dns: Vec<Option<output::scan::host::ReverseDns>>,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let mut reverse_dns = reverse_dns.into_iter();
    for host in hosts {
        let host = output::scan::host::Host::summarize(host, reverse_dns.next().flatten())
            .map_err(CliError::classified)?;
        stream.emit_data(host, Vec::new())?;
    }
    Ok(())
}
