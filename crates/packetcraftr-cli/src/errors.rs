// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{
    core::error::{Classification, Classified, Context, Kind},
    netio as net, output,
};

#[derive(Debug)]
pub(super) struct CliError {
    pub(super) exit_code: u8,
    pub(super) message: String,
    pub(super) classification: Classification,
    context: Option<Box<Context>>,
    pub(super) causes: Vec<String>,
}

impl CliError {
    pub(super) fn new(exit_code: u8, message: impl Into<String>) -> Self {
        let kind = match exit_code {
            2 => Kind::Cli,
            3 => Kind::Packet,
            4 => Kind::Capability,
            5 => Kind::Io,
            6 => Kind::Policy,
            _ => Kind::Internal,
        };
        Self {
            exit_code,
            message: message.into(),
            classification: Classification::new(
                match kind {
                    Kind::Cli => "cli.error",
                    Kind::Packet => "packet.error",
                    Kind::Capability => "capability.unavailable",
                    Kind::Io => "io.runtime",
                    Kind::Policy => "policy.denied",
                    Kind::Internal => "internal.error",
                },
                kind,
                None,
            ),
            context: None,
            causes: Vec::new(),
        }
    }

    pub(super) fn classified(error: impl Classified + std::fmt::Display) -> Self {
        let classification = error.classification();
        let context = error.context();
        let causes = error.causes();
        Self::from_classification(classification, error.to_string(), causes).with_context(context)
    }

    pub(super) fn from_classification(
        classification: Classification,
        message: impl Into<String>,
        causes: Vec<String>,
    ) -> Self {
        Self {
            exit_code: exit_code_for_kind(classification.kind),
            message: message.into(),
            classification,
            context: None,
            causes,
        }
    }

    pub(super) fn with_context(mut self, context: Context) -> Self {
        self.context = (!context.is_empty()).then(|| Box::new(context));
        self
    }

    pub(super) fn into_boundary_error(self) -> packetcraftr::BoundaryError {
        let context = self.context.as_deref().copied().unwrap_or_default();
        packetcraftr::BoundaryError::new(self.message, self.classification, self.causes)
            .with_context(context)
    }

    pub(super) fn with_cleanup(mut self, cleanup: net::Error) -> Self {
        let operation = self.message.clone();
        self.message = format!("{operation}; capture shutdown also failed: {cleanup}");
        if self.causes.is_empty() {
            self.causes.push(operation);
        }
        self.causes.push(cleanup.to_string());
        self
    }

    pub(super) fn output_error(&self) -> output::envelope::Error {
        let context = self.context.as_deref().copied().unwrap_or_default();
        output::envelope::Error::new(
            self.classification,
            self.message.clone(),
            self.causes.clone(),
        )
        .with_context(context)
    }
}

/// The NDJSON encoder reports failures without an exit code, and every CLI
/// failure path starts from a [`CliError`].
impl From<output::envelope::EncodeError> for CliError {
    fn from(error: output::envelope::EncodeError) -> Self {
        Self::classified(error)
    }
}

const fn exit_code_for_kind(kind: Kind) -> u8 {
    match kind {
        Kind::Cli => 2,
        Kind::Packet => 3,
        Kind::Capability => 4,
        Kind::Io => 5,
        Kind::Policy => 6,
        Kind::Internal => 70,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_exit_codes_map_to_stable_classifications() {
        let cases = [
            (2, Kind::Cli, "cli.error"),
            (3, Kind::Packet, "packet.error"),
            (4, Kind::Capability, "capability.unavailable"),
            (5, Kind::Io, "io.runtime"),
            (6, Kind::Policy, "policy.denied"),
            (1, Kind::Internal, "internal.error"),
            (70, Kind::Internal, "internal.error"),
        ];

        for (exit_code, kind, code) in cases {
            let error = CliError::new(exit_code, "failure");
            assert_eq!(error.classification.kind, kind, "exit {exit_code}");
            assert_eq!(error.classification.code, code, "exit {exit_code}");
        }
    }

    #[test]
    fn classified_errors_preserve_causes_and_boundary_contracts() {
        let classified = packetcraftr::BoundaryError::new(
            "fixture failed",
            Classification::new(
                "fixture.denied",
                Kind::Policy,
                Some("authorize the fixture"),
            ),
            vec!["first cause".to_owned(), "second cause".to_owned()],
        )
        .with_context(Context::probe_sequence(42));
        let error = CliError::classified(classified);
        assert_eq!(error.exit_code, 6);

        let output = error.output_error();
        assert_eq!(output.code, "fixture.denied");
        assert_eq!(output.causes, ["first cause", "second cause"]);
        assert_eq!(output.remediation.as_deref(), Some("authorize the fixture"));
        assert_eq!(output.context.probe_sequence, Some(42));

        let boundary = error.into_boundary_error();
        assert_eq!(boundary.classification().code, "fixture.denied");
        assert_eq!(boundary.causes(), ["first cause", "second cause"]);
        assert_eq!(boundary.context().probe_sequence, Some(42));
    }

    #[test]
    fn ndjson_encode_failures_keep_their_classification_and_exit_code() {
        let write = output::envelope::EncodeError::Write {
            sequence: 3,
            source: std::io::Error::other("sink closed"),
        };
        let error = CliError::from(write);
        assert_eq!(error.exit_code, 5);
        assert_eq!(error.classification.code, "io.stdout");
        assert!(error.message.contains("sequence 3"));

        let terminated = CliError::from(output::envelope::EncodeError::Terminal);
        assert_eq!(terminated.exit_code, 70);
        assert_eq!(terminated.classification.code, "internal.ndjson_stream");
    }

    #[test]
    fn cleanup_failure_keeps_the_primary_error() {
        let cleanup = net::Error::Capture {
            message: "receiver stopped".to_owned(),
        };
        let error = CliError::new(5, "capture failed").with_cleanup(cleanup.clone());
        assert_eq!(
            error.message,
            format!("capture failed; capture shutdown also failed: {cleanup}")
        );
        assert_eq!(
            error.causes,
            vec!["capture failed".to_owned(), cleanup.to_string()]
        );

        let error = CliError::from_classification(
            Classification::new("io.fixture", Kind::Io, None),
            "capture failed",
            vec!["original source".to_owned()],
        )
        .with_cleanup(cleanup.clone());
        assert_eq!(
            error.causes,
            vec!["original source".to_owned(), cleanup.to_string()]
        );
    }
}
