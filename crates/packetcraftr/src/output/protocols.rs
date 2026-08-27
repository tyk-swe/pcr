// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Built-in protocol discovery output.

use serde::Serialize;

use packetcraftr_core::field::FieldKind as CoreFieldKind;
use packetcraftr_core::layer::FieldSchema;
use packetcraftr_core::protocol::support;

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

mirror_enum! {
    /// Stable reflective field type owned by the output contract.
    #[serde(rename_all = "snake_case")]
    pub enum FieldKind from CoreFieldKind {
        Bool = Bool,
        Unsigned = Unsigned,
        Signed = Signed,
        Text = Text,
        Bytes = Bytes,
        Ipv4 = Ipv4,
        Ipv6 = Ipv6,
        Mac = Mac,
        List = List,
    }
    // This pins the output contract's value set; new kinds require a schema revision and explicit arm.
    unmatched value => unreachable!("field kind {value:?} has no output representation"),
}

impl FieldKind {
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
    pub tier: String,
    pub required: bool,
    pub derived: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    pub aliases: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub element: Option<FieldKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<u64>,
    pub description: String,
}

impl From<&FieldSchema> for Field {
    fn from(value: &FieldSchema) -> Self {
        Self {
            name: value.name.to_owned(),
            kind: value.kind.into(),
            tier: match value.tier {
                packetcraftr_core::layer::Tier::Required => "required".to_owned(),
                packetcraftr_core::layer::Tier::Derived => "derived".to_owned(),
                packetcraftr_core::layer::Tier::Optional => "optional".to_owned(),
            },
            required: value.is_required(),
            derived: value.is_derived(),
            default: value.default.map(ToOwned::to_owned),
            aliases: value
                .aliases
                .iter()
                .map(|alias| (*alias).to_owned())
                .collect(),
            element: value.element.map(Into::into),
            max: value.max,
            description: value.description.to_owned(),
        }
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

/// Aggregate result of `protocols <name> --example`: a minimal document
/// snippet that builds this protocol's layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExampleResult {
    pub protocol: String,
    pub decode_only: bool,
    pub example: String,
}
