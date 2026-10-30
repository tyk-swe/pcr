// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::envelope::Published;
use packetcraftr_core::analysis;

use crate::errors::CliError;
use crate::invocation::StreamEncoder;
use crate::output::contract::Format;

pub(crate) fn ip_event_sink(
    format: Format,
    stream: &StreamEncoder,
) -> impl FnMut(analysis::IpEventRecord) -> Result<(), packetcraftr_core::error::BoundaryError> {
    let stream = (format == Format::Ndjson).then(|| stream.clone());
    move |event| {
        if let Some(stream) = &stream {
            stream
                .emit_published(Published::new(
                    crate::output::reassembly::Event::from(event),
                    Vec::new(),
                ))
                .map_err(|error| CliError::from(error).into_boundary_error())?;
        }
        Ok(())
    }
}

pub(crate) fn render_scope(
    invocation: &crate::invocation::Invocation,
    scope: &analysis::scope::Definition,
) -> Result<(), CliError> {
    let scope = crate::output::analysis::Scope::try_from(scope.clone())?;
    crate::rendering::write_stdout_line(
        invocation,
        format_args!(
            "scope {}: interface {}, encapsulation {}",
            scope.id,
            crate::rendering::render_optional(scope.interface, |value| value.to_string()),
            crate::rendering::encapsulation_text(&scope.encapsulation)
        ),
    )
}

pub(crate) fn render_clock(
    invocation: &crate::invocation::Invocation,
    clock: &analysis::ClockReport,
) -> Result<(), CliError> {
    crate::rendering::write_stdout_line(
        invocation,
        format_args!(
            "capture clock: {} regressing frame(s), largest rollback {}, largest forward step {} at frame {}; expiry follows the high-water mark",
            clock.regressions,
            crate::rendering::duration_text(clock.max_regression),
            crate::rendering::duration_text(clock.max_forward_step),
            crate::rendering::render_optional(clock.max_forward_step_frame, |value| value
                .to_string()),
        ),
    )
}
