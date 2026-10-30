// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::{contract::Format, stream::StreamRecord};
use crate::{errors::CliError, rendering::bounded_json_len};
use packetcraftr_core::error::Kind;

pub(crate) struct EventOutput<'a> {
    format: Format,
    invocation: &'a crate::invocation::Invocation,
    remaining: usize,
}

impl<'a> EventOutput<'a> {
    pub(crate) fn new(invocation: &'a crate::invocation::Invocation, maximum: usize) -> Self {
        Self {
            format: invocation.format,
            invocation,
            remaining: maximum,
        }
    }

    pub(crate) fn emit<T: StreamRecord>(
        &mut self,
        value: T,
        retained: &mut Vec<T>,
        render_text: impl FnOnce(&crate::invocation::Invocation, &T) -> Result<(), CliError>,
    ) -> Result<(), CliError> {
        if self.format == Format::Ndjson {
            return self
                .invocation
                .output
                .emit_data_counted(value, Vec::new(), &mut self.remaining)
                .map_err(|error| match error {
                    crate::output::stream::MeteredError::Limit => limit_error(),
                    crate::output::stream::MeteredError::Encode(error) => CliError::from(error),
                    crate::output::stream::MeteredError::Serialize(error) => {
                        super::machine::serialization_error(error)
                    }
                });
        }
        let bytes = bounded_json_len(&value, self.remaining, serde_json::ser::CompactFormatter)
            .map_err(|error| error.into_cli_error(limit_error))?;
        self.remaining -= bytes;
        match self.format {
            Format::Json => retained.push(value),
            Format::Ndjson => {
                unreachable!("NDJSON is emitted and charged in one serialization above")
            }
            Format::Text => render_text(self.invocation, &value)?,
            other => other.unreachable(),
        }
        Ok(())
    }
}

fn limit_error() -> CliError {
    CliError::new(
        Kind::Policy,
        "application output exceeds --max-application-output-bytes",
    )
}

#[cfg(test)]
mod tests;
