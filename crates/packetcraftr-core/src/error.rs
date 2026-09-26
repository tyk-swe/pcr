// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Stable failure taxonomy shared by the Rust API and command-line renderer.

use std::sync::Arc;

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
///
/// Kinds are neutral: each front end decides how a kind is published and which
/// exit status it maps to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A caller or request error: the input or invocation was wrong, not the
    /// packet or environment.
    Usage,
    Packet,
    Capability,
    Io,
    Policy,
    Internal,
}

impl Kind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Usage => "usage",
            Self::Packet => "packet",
            Self::Capability => "capability",
            Self::Io => "io",
            Self::Policy => "policy",
            Self::Internal => "internal",
        }
    }
}

display_via_as_str!(Kind);

/// Deterministic machine code, failure kind, and operator guidance for an error.
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

/// A shared, type-erased error source: the one way core stores a source whose
/// type it does not name, so the error holding it stays `Clone`.
///
/// It is the source's handle, not a link of its own: a `#[source]` field of
/// this type exposes the wrapped error itself, so `downcast_ref` reaches it.
/// Two handles are equal when they share the error or render the same chain.
#[derive(Clone)]
pub struct Source(Arc<dyn std::error::Error + Send + Sync>);

impl Source {
    pub fn new(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self(Arc::new(error))
    }
}

impl<E: std::error::Error + Send + Sync + 'static> From<E> for Source {
    fn from(error: E) -> Self {
        Self::new(error)
    }
}

impl std::ops::Deref for Source {
    type Target = dyn std::error::Error + Send + Sync;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl std::fmt::Debug for Source {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::fmt::Display for Source {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl PartialEq for Source {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0) || render(&**self) == render(&**other)
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

/// Renders an error and every distinct source as one `": "`-joined line.
///
/// Only for the text records a failure is published into, such as
/// diagnostics and malformed-layer reasons, which cannot hold a source chain.
/// An error that crosses a boundary keeps its sources instead.
///
/// ```
/// use packetcraftr_core::error::render;
///
/// #[derive(Debug, thiserror::Error)]
/// #[error("invalid dns layer")]
/// struct Outer(#[source] std::io::Error);
///
/// let error = Outer(std::io::Error::other("label too long"));
/// assert_eq!(render(&error), "invalid dns layer: label too long");
/// ```
#[must_use]
pub fn render(error: &(dyn std::error::Error + '_)) -> String {
    let mut text = error.to_string();
    for cause in source_chain(error) {
        text.push_str(": ");
        text.push_str(&cause);
    }
    text
}

/// Implemented by public errors that cross a live-workflow or CLI boundary.
pub trait Classified: std::error::Error {
    fn classification(&self) -> Classification;

    /// The stable domain coordinate for automation and partial-stream
    /// recovery, when the failure has one.
    fn context(&self) -> Option<Coordinate> {
        None
    }

    /// Ordered source diagnostics for structured rendering; the main error
    /// remains authoritative. Defaults to [`source_chain`]; overrides handle
    /// paired failures, captured snapshots, and their wrappers.
    fn causes(&self) -> Vec<String> {
        source_chain(self)
    }
}
