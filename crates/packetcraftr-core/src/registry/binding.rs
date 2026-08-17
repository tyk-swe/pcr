// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::layer::Id as ProtocolId;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Discriminator(pub u64);

/// How one display-filter path resolves onto reflective layer fields.
///
/// Canonical `<protocol>.<field>` paths need no binding: the filter compiler
/// resolves them directly against [`crate::registry::Registry::schema`]. Bindings exist
/// so a protocol can additionally publish the conventional spellings operators
/// already type, and so a packed field can be addressed one flag at a time.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FilterFieldBinding {
    /// An alternate spelling of one reflective field.
    Direct {
        protocol: ProtocolId,
        field: &'static str,
    },
    /// One sub-value of a packed unsigned field, such as a single TCP flag.
    ///
    /// The field value is masked and then shifted right, so a single flag bit
    /// compares against `0` and `1` rather than its raw positional weight.
    Bits {
        protocol: ProtocolId,
        field: &'static str,
        mask: u64,
        shift: u32,
    },
    /// Several reflective fields addressed by one path, such as a port that
    /// may appear as either endpoint. A comparison holds when **any** listed
    /// field satisfies it.
    Either {
        protocol: ProtocolId,
        fields: &'static [&'static str],
    },
}

impl FilterFieldBinding {
    /// The protocol whose layers this path reads.
    pub fn protocol(&self) -> &ProtocolId {
        match self {
            Self::Direct { protocol, .. }
            | Self::Bits { protocol, .. }
            | Self::Either { protocol, .. } => protocol,
        }
    }

    /// Every reflective field name this path may read.
    pub fn fields(&self) -> &[&'static str] {
        match self {
            Self::Direct { field, .. } | Self::Bits { field, .. } => std::slice::from_ref(field),
            Self::Either { fields, .. } => fields,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct ChildBinding {
    pub(super) child: ProtocolId,
    pub(super) priority: i32,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ReverseBinding {
    pub(super) discriminator: Discriminator,
    pub(super) priority: i32,
}
