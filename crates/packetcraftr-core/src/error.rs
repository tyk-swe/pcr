// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use serde::Serialize;

mod boundary;

pub use boundary::BoundaryError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Coordinate {
    /// One-based position of the source frame in its capture.
    SourceFrame(u64),
    ProbeSequence(u64),
    /// One-based attempt number within one request.
    Attempt(u32),
    /// Zero-based fuzz case index within a campaign.
    CaseIndex(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
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

pub trait Classified: std::error::Error {
    fn classification(&self) -> Classification;

    fn context(&self) -> Option<Coordinate> {
        None
    }

    fn causes(&self) -> Vec<String> {
        source_chain(self)
    }
}

impl Classified for std::convert::Infallible {
    fn classification(&self) -> Classification {
        match *self {}
    }
}
