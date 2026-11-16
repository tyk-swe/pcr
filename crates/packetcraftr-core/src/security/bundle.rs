// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{Error, Report, Source};

pub const SCHEMA: &str = "packetcraftr.bundle/v1";
pub const MAX_BUNDLE_DOCUMENT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeRef {
    pub label: String,
    pub digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub schema: String,
    pub tool_version: String,
    pub kind: String,
    pub scope: Option<ScopeRef>,
    pub inputs_digest: String,
    pub sources: Vec<Source>,
    pub report: Report,
}

fn inputs_digest(sources: &[Source]) -> String {
    let mut lines: Vec<String> = sources
        .iter()
        .map(|source| format!("{}\n{}\n", source.path, source.sha256))
        .collect();
    lines.sort();
    crate::field::hex::compact_hex(&Sha256::digest(lines.concat().as_bytes()))
}

impl Bundle {
    #[must_use]
    pub fn new(report: Report, scope: Option<ScopeRef>) -> Self {
        Self {
            schema: SCHEMA.to_owned(),
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            kind: report.kind.clone(),
            scope,
            inputs_digest: inputs_digest(&report.sources),
            sources: report.sources.clone(),
            report,
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BUNDLE_DOCUMENT_BYTES {
            return Err(Error::Limit {
                field: "bundle_bytes",
                limit: MAX_BUNDLE_DOCUMENT_BYTES,
            });
        }
        let bundle: Self =
            serde_json::from_slice(bytes).map_err(|source| Error::Invalid(source.to_string()))?;
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn validate(&self) -> Result<(), Error> {
        let invalid = |reason: &str| Err(Error::Invalid(reason.to_owned()));
        if self.schema != SCHEMA {
            return invalid("expected a packetcraftr.bundle/v1 document");
        }
        if self.tool_version.is_empty() || self.kind.is_empty() || self.kind != self.report.kind {
            return invalid("bundle kind must match the embedded report kind");
        }
        if self.sources.is_empty() {
            return invalid("bundle must record at least one input source");
        }
        let same_sources = self.sources.len() == self.report.sources.len()
            && self
                .sources
                .iter()
                .zip(&self.report.sources)
                .all(|(left, right)| left.path == right.path && left.sha256 == right.sha256);
        if !same_sources {
            return invalid("bundle sources must match the embedded report sources");
        }
        if self.inputs_digest != inputs_digest(&self.sources) {
            return invalid("bundle inputs_digest does not match its sources");
        }
        if let Some(scope) = &self.scope
            && (scope.label.trim().is_empty()
                || scope.label.chars().count() > 128
                || scope.label.chars().any(char::is_control)
                || scope.digest.len() != 64
                || !scope.digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return invalid("bundle scope needs a printable label and a SHA-256 digest");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{Finding, Severity};

    fn bundle() -> Bundle {
        let mut report = Report::new("report");
        report.sources.push(Source {
            path: "scan.json".into(),
            sha256: "a".repeat(64),
        });
        report.findings.push(Finding::new(
            "engagement.scan.summary",
            Severity::Info,
            "scan",
            "observed",
            serde_json::json!({"endpoints": 1}),
            "none",
        ));
        Bundle::new(
            report,
            Some(ScopeRef {
                label: "lab".into(),
                digest: "b".repeat(64),
            }),
        )
    }

    #[test]
    fn bundle_round_trips_and_binds_its_sources() {
        let bundle = bundle();
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let parsed = Bundle::parse(&bytes).unwrap();
        assert_eq!(parsed.kind, "report");
        assert_eq!(parsed.report.findings.len(), 1);
        assert_eq!(parsed.scope.unwrap().label, "lab");
    }

    #[test]
    fn tampered_sources_and_wrong_schema_are_rejected() {
        let mut tampered = bundle();
        tampered.sources[0].sha256 = "c".repeat(64);
        tampered.report.sources[0].sha256 = "c".repeat(64);
        assert!(tampered.validate().is_err());

        let mut wrong = bundle();
        wrong.schema = "packetcraftr.bundle/v2".into();
        assert!(wrong.validate().is_err());

        let mut mismatched = bundle();
        mismatched.report.sources.clear();
        assert!(mismatched.validate().is_err());
    }
}
