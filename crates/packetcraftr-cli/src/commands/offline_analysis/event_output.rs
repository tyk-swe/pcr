// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::{contract::Format, stream::StreamRecord};
use crate::{
    errors::CliError,
    publication::{bounded_json_len, bounded_pretty_item_len},
    terminal::write_stdout_block,
};
use packetcraftr_core::error::Kind;
use serde::Serialize;

pub(crate) struct EventOutput<'a> {
    invocation: &'a crate::invocation::Invocation,
    remaining: usize,
}

impl<'a> EventOutput<'a> {
    pub(crate) fn new(invocation: &'a crate::invocation::Invocation, maximum: usize) -> Self {
        Self {
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
        if self.format() == Format::Ndjson {
            return self.emit_ndjson(value);
        }
        let bytes = bounded_json_len(&value, self.remaining, serde_json::ser::CompactFormatter)
            .map_err(|error| error.into_cli_error(limit_error))?;
        self.remaining -= bytes;
        match self.format() {
            Format::Json => retained.push(value),
            Format::Ndjson => {
                unreachable!("NDJSON is emitted and charged in one serialization above")
            }
            Format::Text => render_text(self.invocation, &value)?,
            other => other.unreachable(),
        }
        Ok(())
    }

    pub(crate) fn format(&self) -> Format {
        self.invocation.format
    }

    pub(crate) fn emit_ndjson(&mut self, value: impl StreamRecord) -> Result<(), CliError> {
        self.invocation
            .output
            .emit_data_counted(value, Vec::new(), &mut self.remaining)
            .map_err(|error| crate::publication::metered_error(error, limit_error))
    }

    pub(crate) fn retain_pretty_item<T: Serialize>(
        &mut self,
        value: T,
        retained: &mut Vec<T>,
        depth: usize,
    ) -> Result<(), CliError> {
        let bytes = bounded_pretty_item_len(&value, self.remaining, depth, retained.is_empty())
            .map_err(|error| error.into_cli_error(limit_error))?;
        self.remaining -= bytes;
        retained.push(value);
        Ok(())
    }

    pub(crate) fn emit_text(&mut self, block: &str) -> Result<(), CliError> {
        self.remaining = self
            .remaining
            .checked_sub(block.len())
            .ok_or_else(limit_error)?;
        write_stdout_block(self.invocation, block)
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
