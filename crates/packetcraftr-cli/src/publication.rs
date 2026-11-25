// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod bounded;
mod bytes;
mod json;
mod ndjson;

pub(crate) use bounded::{
    BoundedJsonError, Limited, bounded_json_len, bounded_pretty_field_len, bounded_pretty_item_len,
};
pub(crate) use bytes::{write_hex_line, write_raw};
pub(crate) use json::{emit_json, emit_published, serialization_error, write_pretty_json_buffered};
pub(crate) use ndjson::{stdout_stream, write_unattributed_error};

use crate::errors::CliError;
use crate::output::stream::MeteredError;

pub(crate) fn metered_error(error: MeteredError, limit: impl FnOnce() -> CliError) -> CliError {
    match error {
        MeteredError::Limit => limit(),
        MeteredError::Encode(error) => CliError::from(error),
        MeteredError::Serialize(error) => serialization_error(error),
    }
}
