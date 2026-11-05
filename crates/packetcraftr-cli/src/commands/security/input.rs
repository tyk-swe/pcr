// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::invalid;
use crate::errors::CliError;
use packetcraftr_core::security::{Report, Source, input};
use sha2::{Digest, Sha256};
use std::path::Path;

pub(in crate::commands) fn read(
    invocation: &crate::invocation::Invocation,
    path: &Path,
    limit: usize,
) -> Result<Vec<u8>, CliError> {
    if path == Path::new("-") {
        crate::input::read_stdin_bounded_allow_empty(
            invocation,
            limit,
            crate::input::InputKind::SecurityDocument,
        )
    } else {
        crate::input::read_bounded_json_document(invocation, path, limit)
    }
}

/// A pipe has one consumer; reject ambiguous inputs before consuming any bytes.
pub(in crate::commands) fn validate_stdin_sources<'a>(
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

pub(in crate::commands) fn source(path: &Path, bytes: &[u8]) -> Source {
    Source {
        path: path.display().to_string(),
        sha256: crate::output::hex::compact_hex(&Sha256::digest(bytes)),
    }
}

/// Validate the published envelope before admitting an assessment's input report.
pub(in crate::commands) fn report(bytes: &[u8]) -> Result<Report, CliError> {
    let envelope = input::aggregate::<Report>(
        bytes,
        &[
            "hunt",
            "dns-anomalies",
            "beacons",
            "audit-tls",
            "audit-http",
            "scan-diff",
        ],
    )
    .map_err(|error| invalid(error.to_string()))?;
    if envelope.result.kind != envelope.command {
        return Err(invalid("report kind does not match command"));
    }
    Ok(envelope.result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_hunt() -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../examples/documents/output-hunt-success.json"),
        )
        .unwrap()
    }

    fn hunt_with_schema(schema: &str) -> Vec<u8> {
        let mut value: serde_json::Value = serde_json::from_slice(&current_hunt()).unwrap();
        value["schema"] = serde_json::Value::from(schema);
        serde_json::to_vec(&value).unwrap()
    }

    fn rejection(bytes: &[u8]) -> String {
        report(bytes).unwrap_err().message
    }

    #[test]
    fn current_security_output_is_accepted() {
        assert_eq!(report(&current_hunt()).unwrap().kind, "hunt");
    }

    #[test]
    fn v1_reports_require_regeneration() {
        let message = rejection(&hunt_with_schema("packetcraftr.output/v1"));
        assert!(message.contains("ambiguous"), "{message}");
        assert!(message.contains("regenerate"), "{message}");
    }

    #[test]
    fn unrelated_output_identity_is_rejected() {
        for schema in [
            "packetcraftr.output/v2",
            "packetcraftr.output/v18",
            "packetcraftr.output/v20",
        ] {
            let message = rejection(&hunt_with_schema(schema));
            assert!(!message.contains("ambiguous"), "{schema}: {message}");
        }
    }

    #[test]
    fn deeply_nested_report_json_is_rejected() {
        let depth = 100_000;
        let nested = [vec![b'['; depth], vec![b']'; depth]].concat();
        assert!(report(&nested).is_err());
    }

    #[test]
    fn stdin_validation_precedes_io_and_hashes_input() {
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
