// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Built-in protocol discovery output.

use serde::Serialize;

use packetcraftr_core::field::FieldKind as CoreFieldKind;
use packetcraftr_core::layer::FieldSchema;
use packetcraftr_core::protocol::support;

use super::contract::Error as ContractError;

/// Capability summary for one built-in protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub protocol: String,
    pub aliases: Vec<String>,
    pub build: bool,
    pub dissect: bool,
    pub exact_round_trip: bool,
    pub matcher: bool,
    pub decode_only: bool,
}

impl From<&support::Protocol> for Summary {
    fn from(value: &support::Protocol) -> Self {
        Self {
            protocol: value.protocol.to_owned(),
            aliases: value
                .aliases
                .iter()
                .map(|alias| (*alias).to_owned())
                .collect(),
            build: value.build,
            dissect: value.dissect,
            exact_round_trip: value.exact_round_trip,
            matcher: value.matcher,
            decode_only: value.decode_only,
        }
    }
}

/// Stable reflective field type owned by the output-v1 contract.
///
/// v1 pins this value set. [`CoreFieldKind`] is `#[non_exhaustive]`, so a kind
/// added there before the schema is revised has no representation here and is
/// reported rather than guessed at — `protocols --detail` is a descriptive
/// path and must not abort on one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Bool,
    Unsigned,
    Signed,
    Text,
    Bytes,
    Ipv4,
    Ipv6,
    Mac,
    List,
}

impl FieldKind {
    /// The v1 representation of one core field kind, or `None` when this
    /// contract has no name for it.
    #[must_use]
    pub const fn from_core(kind: CoreFieldKind) -> Option<Self> {
        match kind {
            CoreFieldKind::Bool => Some(Self::Bool),
            CoreFieldKind::Unsigned => Some(Self::Unsigned),
            CoreFieldKind::Signed => Some(Self::Signed),
            CoreFieldKind::Text => Some(Self::Text),
            CoreFieldKind::Bytes => Some(Self::Bytes),
            CoreFieldKind::Ipv4 => Some(Self::Ipv4),
            CoreFieldKind::Ipv6 => Some(Self::Ipv6),
            CoreFieldKind::Mac => Some(Self::Mac),
            CoreFieldKind::List => Some(Self::List),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::Unsigned => "unsigned",
            Self::Signed => "signed",
            Self::Text => "text",
            Self::Bytes => "bytes",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Mac => "mac",
            Self::List => "list",
        }
    }
}

/// One ordered reflective field exposed by a built-in protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Field {
    pub name: String,
    pub kind: FieldKind,
    pub required: bool,
    pub derived: bool,
    pub description: String,
}

impl TryFrom<&FieldSchema> for Field {
    type Error = ContractError;

    fn try_from(value: &FieldSchema) -> Result<Self, Self::Error> {
        Ok(Self {
            name: value.name.to_owned(),
            kind: FieldKind::from_core(value.kind).ok_or_else(|| {
                ContractError::UnsupportedFieldKind {
                    field: value.name.to_owned(),
                }
            })?,
            required: value.required,
            derived: value.derived,
            description: value.description.to_owned(),
        })
    }
}

/// One registered edge that reaches a protocol during dissection.
///
/// `discriminator` is the parent's selector value: a TCP or UDP port, an
/// EtherType, an IP protocol number. Zero is the parent's fallback binding,
/// used when nothing more specific matches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Binding {
    pub parent: String,
    pub discriminator: u64,
}

/// Detailed capability and reflection data for one built-in protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Detail {
    pub protocol: String,
    pub aliases: Vec<String>,
    pub build: bool,
    pub dissect: bool,
    pub exact_round_trip: bool,
    pub matcher: bool,
    pub decode_only: bool,
    pub fields: Vec<Field>,
    pub bindings: Vec<Binding>,
}

impl Detail {
    pub fn new(summary: Summary, fields: Vec<Field>, bindings: Vec<Binding>) -> Self {
        Self {
            protocol: summary.protocol,
            aliases: summary.aliases,
            build: summary.build,
            dissect: summary.dissect,
            exact_round_trip: summary.exact_round_trip,
            matcher: summary.matcher,
            decode_only: summary.decode_only,
            fields,
            bindings,
        }
    }
}

/// Aggregate result of listing built-in protocols.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ListResult {
    pub protocols: Vec<Summary>,
}

/// Aggregate result of describing one built-in protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DetailResult {
    pub protocol: Detail,
}
