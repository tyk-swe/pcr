// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Common capture-analysis rendering and IP reassembly event publication.

use packetcraftr_core::analysis;

use super::StreamEncoder;
use crate::errors::CliError;

/// Sink for IP reassembly lifecycle events, which only the NDJSON stream
/// carries. The other formats fold the same information into their terminal
/// `ip_reassembly` report, so a non-NDJSON `format` drops every event.
pub(crate) fn ip_event_sink<F>(
    format: F,
    stream: &StreamEncoder,
) -> impl FnMut(analysis::IpEventRecord) -> Result<(), packetcraftr_core::error::BoundaryError>
where
    F: Into<crate::output::contract::Format>,
{
    let stream = (format.into() == crate::output::contract::Format::Ndjson).then(|| stream.clone());
    move |event| {
        if let Some(stream) = &stream {
            stream
                .emit_data(crate::output::reassembly::Event::from(event), Vec::new())
                .map_err(|error| CliError::from(error).into_boundary_error())?;
        }
        Ok(())
    }
}

pub(crate) fn render_scope(scope: &analysis::scope::Definition) -> Result<(), CliError> {
    let scope = crate::output::analysis::Scope::try_from(scope.clone())?;
    crate::rendering::write_stdout_line(format_args!(
        "scope {}: interface {}, encapsulation {}",
        scope.id,
        crate::rendering::optional_display(scope.interface),
        crate::rendering::encapsulation_text(&scope.encapsulation)
    ))
}

pub(crate) fn render_clock(clock: &analysis::ClockReport) -> Result<(), CliError> {
    crate::rendering::write_stdout_line(format_args!(
        "capture clock: {} regressing frame(s), largest rollback {}, largest forward step {} at frame {}; expiry follows the high-water mark",
        clock.regressions,
        crate::rendering::duration_text(clock.max_regression),
        crate::rendering::duration_text(clock.max_forward_step),
        crate::rendering::optional_display(clock.max_forward_step_frame),
    ))
}
