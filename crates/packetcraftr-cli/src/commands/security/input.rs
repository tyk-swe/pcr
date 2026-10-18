// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::invalid;
use crate::errors::CliError;
use packetcraftr_core::security::{Report, Source};
use sha2::{Digest, Sha256};
use std::path::Path;

pub(super) fn read(path: &Path, limit: usize) -> Result<Vec<u8>, CliError> {
    if path == Path::new("-") {
        crate::input::read_stdin_bounded_allow_empty(
            limit,
            crate::input::InputKind::SecurityDocument,
        )
    } else {
        crate::input::read_bounded_json_document(path, limit)
    }
}

/// A pipe has one consumer; reject ambiguous inputs before consuming any bytes.
pub(super) fn validate_stdin_sources<'a>(
    paths: impl IntoIterator<Item = &'a Path>,
) -> Result<(), CliError> {
    if paths
        .into_iter()
        .filter(|path| *path == Path::new("-"))
        .take(2)
        .count()
        > 1
    {
        return Err(invalid("only one input may read stdin (-) per command"));
    }
    Ok(())
}

pub(super) fn source(path: &Path, bytes: &[u8]) -> Source {
    Source {
        path: path.display().to_string(),
        sha256: Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    }
}

/// Validate the published envelope before admitting an assessment's input report.
pub(super) fn report(bytes: &[u8]) -> Result<Report, CliError> {
    let envelope: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| invalid(e.to_string()))?;
    let command = envelope["command"].as_str().unwrap_or("");
    if envelope["schema"] != "packetcraftr.output/v1"
        || envelope["status"] != "success"
        || envelope["mode"] != "aggregate"
        || ![
            "hunt",
            "dns-anomalies",
            "beacons",
            "audit-tls",
            "audit-http",
            "scan-diff",
        ]
        .contains(&command)
    {
        return Err(invalid(
            "report inputs must be successful aggregate JSON from one of the six security commands",
        ));
    }
    let result: Report =
        serde_json::from_value(envelope["result"].clone()).map_err(|e| invalid(e.to_string()))?;
    if result.kind != command {
        return Err(invalid("report kind does not match command"));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_stdin_validation_precedes_io_and_hashes_consumed_bytes() {
        assert!(validate_stdin_sources([Path::new("-"), Path::new("missing.json")]).is_ok());
        assert!(validate_stdin_sources([Path::new("-"), Path::new("-")]).is_err());
        assert!(validate_stdin_sources([Path::new("missing.json")]).is_ok());
        let source = source(Path::new("-"), b"abc");
        assert_eq!(source.path, "-");
        assert_eq!(
            source.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
