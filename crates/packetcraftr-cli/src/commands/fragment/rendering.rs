// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `fragment`'s text output.

use crate::errors::CliError;
use crate::output;
use crate::rendering::write_plain_line;

/// One line per produced fragment: its index, size, and exact bytes.
pub(super) fn render_fragment(fragment: &output::fragment::Fragment) -> Result<(), CliError> {
    write_plain_line(format_args!(
        "fragment {}: {} bytes {}",
        fragment.fragment_index,
        fragment.frame.captured_length,
        fragment.frame.bytes_hex()
    ))
}
