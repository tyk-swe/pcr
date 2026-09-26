// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use crate::output::http as wire;
use crate::rendering::write_plain_line;

pub(super) fn render_message(value: &wire::Message) -> Result<(), CliError> {
    let start = match &value.start {
        Some(wire::StartLine::Request { method, target, .. }) => {
            format!("{method} {}", escaped(target))
        }
        Some(wire::StartLine::Response { status, reason, .. }) => {
            format!("{status} {}", escaped(reason))
        }
        None => "partial headers".to_owned(),
    };
    write_plain_line(format_args!(
        "HTTP tcp:{} message={} {:?} {} body_bytes={} request={:?} frames={:?}",
        value.stream,
        value.index,
        value.status,
        start,
        value.body_bytes,
        value.request,
        value
            .sources
            .iter()
            .map(|source| source.number)
            .collect::<Vec<_>>()
    ))?;
    for header in &value.headers {
        write_plain_line(format_args!(
            "  {}: {}",
            header.name,
            escaped(&header.value)
        ))?;
    }
    if let Some(error) = &value.error {
        write_plain_line(format_args!("  {error}"))?;
    }
    Ok(())
}

pub(super) fn render_issue(value: &wire::Issue) -> Result<(), CliError> {
    write_plain_line(format_args!(
        "  TCP stream={} frame={} {:?}",
        value.0.stream, value.0.number, value.0.status
    ))
}

pub(super) fn escaped(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}
