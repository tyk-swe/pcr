// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Discriminator(pub u64);

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
    pub(super) priority: i32,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ReverseBinding {
    pub(super) discriminator: Discriminator,
    pub(super) priority: i32,
}
