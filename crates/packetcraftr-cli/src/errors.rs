// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::error::Classification;
use packetcraftr_core::error::Classified;
use packetcraftr_core::error::Coordinate;
use packetcraftr_core::error::Kind;

use crate::output;
use crate::output::envelope::source_causes;

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

    pub(crate) fn caused(kind: Kind, source: &(impl std::error::Error + ?Sized)) -> Self {
        Self::from_classification(
            Classification::new(fallback_code(kind), kind, None),
            source.to_string(),
            packetcraftr_core::error::source_chain(source),
        )
    }

    /// The message names what failed; the source's text appears only in the causes.
    pub(crate) fn wrapping(
        kind: Kind,
        message: impl Into<String>,
        source: &(impl std::error::Error + ?Sized),
    ) -> Self {
        Self::from_classification(
            Classification::new(fallback_code(kind), kind, None),
            message,
            source_causes(source),
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

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

impl From<output::stream::EncodeError> for CliError {
    fn from(error: output::stream::EncodeError) -> Self {
        Self::classified(error)
    }
}

impl From<output::contract::Error> for CliError {
    fn from(error: output::contract::Error) -> Self {
        Self::classified(error)
    }
}

/// The source's text, then its distinct sources, for errors whose message omits the source.
const fn fallback_code(kind: Kind) -> &'static str {
    match kind {
        Kind::Usage => "cli.error",
        Kind::Packet => "packet.error",
        Kind::Capability => "capability.unavailable",
        Kind::Io => "io.runtime",
        Kind::Policy => "policy.denied",
        Kind::Internal => "internal.error",
    }
}

/// Every failure class in exit-code order.
pub(crate) const KINDS: [Kind; 6] = [
    Kind::Usage,
    Kind::Packet,
    Kind::Capability,
    Kind::Io,
    Kind::Policy,
    Kind::Internal,
];

pub(crate) const CANCELLED_EXIT_CODE: u8 = 130;

pub(crate) const fn exit_code_for(kind: Kind) -> u8 {
    match kind {
        Kind::Usage => 2,
        Kind::Packet => 3,
        Kind::Capability => 4,
        Kind::Io => 5,
        Kind::Policy => 6,
        Kind::Internal => 70,
    }
}

pub(crate) const fn exit_code_description(kind: Kind) -> &'static str {
    match kind {
        Kind::Usage => "the invocation or its input was invalid.",
        Kind::Packet => "the packet could not be built, parsed, or dissected.",
        Kind::Capability => "a native feature, backend, or privilege is unavailable.",
        Kind::Io => "a system or network operation failed.",
        Kind::Policy => "the traffic policy denied the operation.",
        Kind::Internal => "an invariant failed; please report it.",
    }
}
