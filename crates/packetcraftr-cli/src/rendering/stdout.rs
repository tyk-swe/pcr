// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Write};

use packetcraftr_core::error::{Classification, Kind};

use crate::errors::{CliError, source_causes};

pub(super) fn stdout_error(operation: &str, source: io::Error) -> CliError {
    CliError::from_classification(
        Classification::new(
            "io.stdout",
            Kind::Io,
            Some("restore the stdout consumer or choose a writable output destination"),
        ),
        operation,
        source_causes(&source),
    )
}

pub(crate) fn write_raw(bytes: &[u8]) -> Result<(), CliError> {
    write_locked(|stdout| stdout.write_all(bytes))
}

/// Every other stdout line goes through terminal sanitization; this one
/// holds only hex digits by construction, so it is written unstyled and
/// byte-exact.
pub(crate) fn write_hex_line(bytes: &[u8]) -> Result<(), CliError> {
    write_locked(|stdout| {
        stdout.write_fmt(format_args!("{}", crate::output::hex::CompactHex(bytes)))?;
        stdout.write_all(b"\n")
    })
}

fn write_locked(
    write: impl FnOnce(&mut io::StdoutLock<'_>) -> io::Result<()>,
) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    write(&mut stdout)
        .and_then(|()| stdout.flush())
        .map_err(|source| stdout_error("write stdout failed", source))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdout_failures_publish_one_classification_with_remediation() {
        let error = stdout_error("write stdout failed", io::Error::other("consumer closed"));

        assert_eq!(error.exit_code(), 5);
        assert_eq!(error.classification.code, "io.stdout");
        assert!(error.classification.remediation.is_some());
        assert_eq!(error.message, "write stdout failed");
        assert_eq!(error.causes, ["consumer closed"]);
    }
}
