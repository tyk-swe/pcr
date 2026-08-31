// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Stable failure taxonomy shared by the Rust API and command-line renderer.

use serde::Serialize;

mod boundary;

pub use boundary::BoundaryError;

/// The single stable domain coordinate a classified failure carries.
///
/// Externally tagged, so each variant serializes as the one-key object the
/// output contract publishes: `{"source_frame": 7}`, `{"attempt": 3}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Coordinate {
    /// One-based position of the source frame in its capture.
    SourceFrame(u64),
    /// Probe sequence number within a scan or traceroute run.
    ProbeSequence(u64),
    /// One-based attempt number within one request.
    Attempt(u32),
    /// Zero-based fuzz case index within a campaign.
    CaseIndex(u64),
}

/// Top-level failure classes shared by API boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A caller or request error: the input or invocation was wrong, not the
    /// packet or environment.
    Cli,
    Packet,
    Capability,
    Io,
    Policy,
    Internal,
}

impl Kind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Packet => "packet",
            Self::Capability => "capability",
            Self::Io => "io",
            Self::Policy => "policy",
            Self::Internal => "internal",
        }
    }
}

/// Deterministic machine code, CLI class, and operator guidance for an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub struct Classification {
    pub code: &'static str,
    pub kind: Kind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<&'static str>,
}

impl Classification {
    pub const fn new(code: &'static str, kind: Kind, remediation: Option<&'static str>) -> Self {
        Self {
            code,
            kind,
            remediation,
        }
    }
}

/// Every distinct `#[source]` in an error's chain, outermost first.
///
/// The one derivation of [`Classified::causes`] for an error that retains its
/// sources, so no implementor hand-writes the walk. A link whose `Display` is
/// identical to the link above it — what `#[error(transparent)]` and
/// [`BoundaryError::from_error`] both produce — restates the message it wraps
/// and is skipped, so a wrapper never publishes the same sentence twice.
///
/// An error that carries two unrelated failures at once (an operation and the
/// cleanup that also failed) has no single chain and still builds its own
/// list; so does a value type that carries a captured `causes` snapshot rather
/// than live sources.
///
/// ```
/// use packetcraftr_core::error::source_chain;
///
/// #[derive(Debug, thiserror::Error)]
/// #[error("outer")]
/// struct Outer(#[source] Inner);
///
/// #[derive(Debug, thiserror::Error)]
/// #[error("inner")]
/// struct Inner(#[source] std::io::Error);
///
/// let error = Outer(Inner(std::io::Error::other("root")));
/// assert_eq!(source_chain(&error), ["inner", "root"]);
/// ```
#[must_use]
pub fn source_chain(error: &(impl std::error::Error + ?Sized)) -> Vec<String> {
    let mut above = error.to_string();
    let mut causes = Vec::new();
    for source in std::iter::successors(error.source(), |error| (*error).source()) {
        let rendered = source.to_string();
        if rendered != above {
            causes.push(rendered.clone());
        }
        above = rendered;
    }
    causes
}

/// Implemented by public errors that cross a live-workflow or CLI boundary.
pub trait Classified {
    fn classification(&self) -> Classification;

    /// The stable domain coordinate for automation and partial-stream
    /// recovery, when the failure has one.
    fn context(&self) -> Option<Coordinate> {
        None
    }

    /// Ordered source diagnostics retained for structured renderers. The main
    /// error remains authoritative. An error that retains its sources derives
    /// this with [`source_chain`] rather than hand-walking the chain; the
    /// exceptions are dual operation/cleanup failures and value types that
    /// carry a captured snapshot.
    fn causes(&self) -> Vec<String> {
        Vec::new()
    }
}
