// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Discriminator(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatcherIdentity {
    Builtin,
    Conservative,
}

pub(super) struct RegisteredMatcher {
    pub matcher: std::sync::Arc<dyn crate::matcher::ResponseMatcher>,
    pub identity: MatcherIdentity,
}

impl std::fmt::Debug for RegisteredMatcher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegisteredMatcher")
            .field("matcher", &self.matcher)
            .field("identity", &self.identity)
            .finish()
    }
}

impl Clone for RegisteredMatcher {
    fn clone(&self) -> Self {
        Self {
            matcher: self.matcher.clone(),
            identity: self.identity,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    Fallback,
    Secondary,
    Primary,
}

impl Priority {
    pub const fn rank(self) -> i32 {
        match self {
            Self::Fallback => -100,
            Self::Secondary => 90,
            Self::Primary => 100,
        }
    }
}

impl std::fmt::Display for Priority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.rank())
    }
}

impl From<u64> for Discriminator {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

/// Additional display-filter aliases and packed-field selectors.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FilterFieldBinding {
    Direct {
        protocol: crate::layer::Id,
        field: &'static str,
    },
    /// One sub-value of a packed unsigned field, such as a single TCP flag.
    Bits {
        protocol: crate::layer::Id,
        field: &'static str,
        mask: u64,
        shift: u32,
    },
    Either {
        protocol: crate::layer::Id,
        fields: &'static [&'static str],
    },
}

impl FilterFieldBinding {
    pub fn protocol(&self) -> &crate::layer::Id {
        match self {
            Self::Direct { protocol, .. }
            | Self::Bits { protocol, .. }
            | Self::Either { protocol, .. } => protocol,
        }
    }

    pub fn fields(&self) -> &[&'static str] {
        match self {
            Self::Direct { field, .. } | Self::Bits { field, .. } => std::slice::from_ref(field),
            Self::Either { fields, .. } => fields,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct ChildBinding {
    pub(super) child: crate::layer::Id,
    pub(super) priority: Priority,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ReverseBinding {
    pub(super) discriminator: Discriminator,
    pub(super) priority: Priority,
}
