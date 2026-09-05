// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use packetcraftr::output::contract::Format;

use packetcraftr::analysis;

use self::arguments::{Args, Severity};
use super::offline_analysis::prepare_with_tls_ports;
use crate::errors::CliError;
use crate::input::open_capture;
use crate::rendering::StreamEncoder;

fn matches_selector(
    finding: &analysis::expert::Finding,
    min_severity: Severity,
    codes: &[String],
) -> bool {
    if finding.severity < min_severity.into() {
        return false;
    }
    if !codes.is_empty() && !codes.iter().any(|c| c == &finding.code) {
        return false;
    }
    true
}

pub(super) fn run(arguments: Args, format: Format, stream: &StreamEncoder) -> Result<(), CliError> {
    let prepared = prepare_with_tls_ports(
        arguments.limits,
        arguments.filter.as_deref(),
        &arguments.tls_ports.ports,
    )?;
    let mut reader = open_capture(&arguments.path, arguments.limits.capture.reader)?;

    // Expert needs the reassembler's byte-exact retransmission evidence.
    let options = prepared.options(true);
    let mut collector = analysis::expert::Collector::new();
    let mut state = rendering::State::new(arguments.limits.capture.retention_ceiling());
    let outcome = analysis::run_with_ip_events(
        &mut reader,
        prepared.registry.clone(),
        &options,
        super::offline_analysis::ip_event_sink((format == Format::Ndjson).then(|| stream.clone())),
        |record| {
            for finding in collector.observe(&record) {
                if matches_selector(&finding, arguments.min_severity, &arguments.codes) {
                    state.count(&finding);
                    rendering::render_record(format, finding.into(), &mut state, stream)
                        .map_err(CliError::into_boundary_error)?;
                }
            }
            Ok(())
        },
    );
    let summary = outcome.map_err(CliError::classified)?;
    let (trailing, _expert_summary) = collector.finish(&summary);
    for finding in trailing {
        if matches_selector(&finding, arguments.min_severity, &arguments.codes) {
            state.count(&finding);
            rendering::render_record(format, finding.into(), &mut state, stream)?;
        }
    }

    match format {
        Format::Text => rendering::render_text(&summary, &state),
        Format::Json => rendering::render_aggregate(&summary, state),
        Format::Ndjson => rendering::render_stream(&summary, state, stream),
        _ => unreachable!("command dispatch validated the output format"),
    }
}
