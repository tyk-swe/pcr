// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{
    core::error::{Classification, Classified, Coordinate, Kind},
    netio as net, output,
};

#[derive(Debug)]
pub(crate) struct CliError {
    pub(crate) message: String,
    pub(crate) classification: Classification,
    context: Option<Coordinate>,
    pub(crate) causes: Vec<String>,
}

impl CliError {
    /// A CLI-originated failure with the fallback classification for `kind`;
    /// the exit code follows from the kind.
    pub(crate) fn new(kind: Kind, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            classification: Classification::new(fallback_code(kind), kind, None),
            context: None,
            causes: Vec::new(),
        }
    }

    pub(crate) fn classified(error: impl Classified + std::fmt::Display) -> Self {
        let classification = error.classification();
        let context = error.context();
        let causes = error.causes();
        Self::from_classification(classification, error.to_string(), causes).with_context(context)
    }

    pub(crate) fn from_classification(
        classification: Classification,
        message: impl Into<String>,
        causes: Vec<String>,
    ) -> Self {
        Self {
            message: message.into(),
            classification,
            context: None,
            causes,
        }
    }

    /// The process exit code this failure ends in, which is a function of its
    /// classification kind and nothing else.
    pub(crate) const fn exit_code(&self) -> u8 {
        match self.classification.kind {
            Kind::Cli => 2,
            Kind::Packet => 3,
            Kind::Capability => 4,
            Kind::Io => 5,
            Kind::Policy => 6,
            Kind::Internal => 70,
        }
    }

    pub(crate) fn with_context(mut self, context: Option<Coordinate>) -> Self {
        self.context = context;
        self
    }

    pub(crate) fn into_boundary_error(self) -> packetcraftr::BoundaryError {
        packetcraftr::BoundaryError::new(self.message, self.classification, self.causes)
            .with_context(self.context)
    }

    pub(crate) fn with_cleanup(mut self, cleanup: net::Error) -> Self {
        let operation = self.message.clone();
        self.message = format!("{operation}; capture shutdown also failed: {cleanup}");
        if self.causes.is_empty() {
            self.causes.push(operation);
        }
        self.causes.push(cleanup.to_string());
        self
    }

    pub(crate) fn output_error(&self) -> output::envelope::Error {
        output::envelope::Error::new(
            self.classification,
            self.message.clone(),
            self.causes.clone(),
        )
        .with_context(self.context)
    }
}

/// The NDJSON encoder reports failures without an exit code, and every CLI
/// failure path starts from a [`CliError`].
impl From<output::stream::EncodeError> for CliError {
    fn from(error: output::stream::EncodeError) -> Self {
        Self::classified(error)
    }
}

const fn fallback_code(kind: Kind) -> &'static str {
    match kind {
        Kind::Cli => "cli.error",
        Kind::Packet => "packet.error",
        Kind::Capability => "capability.unavailable",
        Kind::Io => "io.runtime",
        Kind::Policy => "policy.denied",
        Kind::Internal => "internal.error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_map_to_stable_exit_codes_and_classifications() {
        let cases = [
            (Kind::Cli, 2, "cli.error"),
            (Kind::Packet, 3, "packet.error"),
            (Kind::Capability, 4, "capability.unavailable"),
            (Kind::Io, 5, "io.runtime"),
            (Kind::Policy, 6, "policy.denied"),
            (Kind::Internal, 70, "internal.error"),
        ];

        for (kind, exit_code, code) in cases {
            let error = CliError::new(kind, "failure");
            assert_eq!(error.exit_code(), exit_code, "kind {kind:?}");
            assert_eq!(error.classification.kind, kind, "kind {kind:?}");
            assert_eq!(error.classification.code, code, "kind {kind:?}");
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
        .with_context(Some(Coordinate::ProbeSequence(42)));
        let error = CliError::classified(classified);
        assert_eq!(error.exit_code(), 6);

        let output = error.output_error();
        assert_eq!(output.code, "fixture.denied");
        assert_eq!(output.causes, ["first cause", "second cause"]);
        assert_eq!(output.remediation.as_deref(), Some("authorize the fixture"));
        assert_eq!(output.context, Some(Coordinate::ProbeSequence(42)));

        let boundary = error.into_boundary_error();
        assert_eq!(boundary.classification().code, "fixture.denied");
        assert_eq!(boundary.causes(), ["first cause", "second cause"]);
        assert_eq!(boundary.context(), Some(Coordinate::ProbeSequence(42)));
    }

    #[test]
    fn ndjson_encode_failures_keep_their_classification_and_exit_code() {
        let write = output::stream::EncodeError::Write {
            sequence: 3,
            source: std::io::Error::other("sink closed"),
        };
        let error = CliError::from(write);
        assert_eq!(error.exit_code(), 5);
        assert_eq!(error.classification.code, "io.stdout");
        assert!(error.message.contains("sequence 3"));

        let terminated = CliError::from(output::stream::EncodeError::Terminal);
        assert_eq!(terminated.exit_code(), 70);
        assert_eq!(terminated.classification.code, "internal.ndjson_stream");
    }

    #[test]
    fn cleanup_failure_keeps_the_primary_error() {
        let cleanup = net::Error::Capture {
            message: "receiver stopped".to_owned(),
            source: None,
        };
        let error = CliError::new(Kind::Io, "capture failed").with_cleanup(cleanup.clone());
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
