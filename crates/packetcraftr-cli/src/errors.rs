// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::error::Classification;
use packetcraftr_core::error::Classified;
use packetcraftr_core::error::Coordinate;
use packetcraftr_core::error::Kind;
#[cfg(test)]
use packetcraftr_netio as net;

use crate::output;

#[derive(Debug)]
pub(crate) struct CliError {
    pub(crate) message: String,
    pub(crate) classification: Classification,
    context: Option<Coordinate>,
    pub(crate) causes: Vec<String>,
    capture: Option<Box<output::capture::Snapshot>>,
    scan: Option<Box<output::scan::Failure>>,
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
            capture: None,
            scan: None,
        }
    }

    pub(crate) fn classified(error: impl Classified + std::fmt::Display) -> Self {
        let classification = error.classification();
        let context = error.context();
        let causes = error.causes();
        Self::from_classification(classification, error.to_string(), causes).with_context(context)
    }

    /// A CLI-originated failure retaining the typed source's rendered chain
    /// in `causes` — for sources that carry no classification of their own.
    pub(crate) fn caused(kind: Kind, source: &(impl std::error::Error + ?Sized)) -> Self {
        Self::from_classification(
            Classification::new(fallback_code(kind), kind, None),
            source.to_string(),
            packetcraftr_core::error::source_chain(source),
        )
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
            capture: None,
            scan: None,
        }
    }

    /// The process exit code this failure ends in, which is a function of its
    /// classification kind and nothing else.
    pub(crate) const fn exit_code(&self) -> u8 {
        exit_code_for(self.classification.kind)
    }

    pub(crate) fn with_context(mut self, context: Option<Coordinate>) -> Self {
        self.context = context;
        self
    }

    pub(crate) fn into_boundary_error(self) -> packetcraftr_core::error::BoundaryError {
        packetcraftr_core::error::BoundaryError::new(self.message, self.classification, self.causes)
            .with_context(self.context)
    }

    pub(crate) fn with_capture(mut self, snapshot: output::capture::Snapshot) -> Self {
        self.capture = Some(Box::new(snapshot));
        self
    }

    pub(crate) fn with_scan(mut self, scan: output::scan::Failure) -> Self {
        self.scan = Some(Box::new(scan));
        self
    }

    pub(crate) fn with_secondary(mut self, phase: &'static str, secondary: Self) -> Self {
        let primary = self.message.clone();
        self.message = format!("{primary}; {phase} also failed: {}", secondary.message);
        if self.causes.is_empty() {
            self.causes.push(primary);
        }
        self.causes.push(secondary.message);
        self.causes.extend(secondary.causes);
        self
    }

    pub(crate) fn output_error(&self) -> output::envelope::Error {
        output::envelope::Error::new(
            self.classification,
            self.message.clone(),
            self.causes.clone(),
        )
        .with_context(self.context)
        .with_capture(self.capture.clone())
        .with_scan(self.scan.clone())
    }
}

/// `CliError` renders its headline message; implementing [`std::error::Error`]
/// lets clap value parsers return it and preserves the classification for
/// callers that read it back.
impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

/// The NDJSON encoder reports failures without an exit code, and every CLI
/// failure path starts from a [`CliError`].
impl From<output::stream::EncodeError> for CliError {
    fn from(error: output::stream::EncodeError) -> Self {
        Self::classified(error)
    }
}

/// Format-contract failures keep their own classification.
impl From<output::contract::Error> for CliError {
    fn from(error: output::contract::Error) -> Self {
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

/// Every failure class in exit-code order; the root `--help` renders its
/// exit-code table from this list.
pub(crate) const KINDS: [Kind; 6] = [
    Kind::Cli,
    Kind::Packet,
    Kind::Capability,
    Kind::Io,
    Kind::Policy,
    Kind::Internal,
];

/// The process exit code after a cooperative interrupt, following the shell
/// convention for SIGINT. It is not a failure [`Kind`]; cancellation is not an
/// error class of the operation itself.
pub(crate) const CANCELLED_EXIT_CODE: u8 = 130;

pub(crate) const fn exit_code_for(kind: Kind) -> u8 {
    match kind {
        Kind::Cli => 2,
        Kind::Packet => 3,
        Kind::Capability => 4,
        Kind::Io => 5,
        Kind::Policy => 6,
        Kind::Internal => 70,
    }
}

/// The one-line meaning of `kind` shown beside its exit code in the root help.
pub(crate) const fn exit_code_description(kind: Kind) -> &'static str {
    match kind {
        Kind::Cli => "the invocation or its input was invalid.",
        Kind::Packet => "the packet could not be built, parsed, or dissected.",
        Kind::Capability => "a native feature, backend, or privilege is unavailable.",
        Kind::Io => "a system or network operation failed.",
        Kind::Policy => "the traffic policy denied the operation.",
        Kind::Internal => "an invariant failed; please report it.",
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
        let classified = packetcraftr_core::error::BoundaryError::new(
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
        let error = CliError::new(Kind::Io, "capture failed")
            .with_secondary("capture shutdown", CliError::classified(cleanup.clone()));
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
        .with_secondary("capture shutdown", CliError::classified(cleanup.clone()));
        assert_eq!(
            error.causes,
            vec!["original source".to_owned(), cleanup.to_string()]
        );
    }
}
