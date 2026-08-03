// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::packet;

use crate::errors::CliError;
use crate::rendering::emit_stderr_message;

pub(super) fn render_diagnostics_stderr(
    diagnostics: &[packet::diagnostic::Diagnostic],
) -> Result<(), CliError> {
    for diagnostic in diagnostics {
        emit_stderr_message(&format!(
            "{:?} {}: {}",
            diagnostic.severity, diagnostic.code, diagnostic.message
        ))?;
    }
    Ok(())
}
