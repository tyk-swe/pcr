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

/// Stable reflective field type owned by the output-v1 contract.
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

impl From<CoreFieldKind> for FieldKind {
    fn from(value: CoreFieldKind) -> Self {
        match value {
            CoreFieldKind::Bool => Self::Bool,
            CoreFieldKind::Unsigned => Self::Unsigned,
            CoreFieldKind::Signed => Self::Signed,
            CoreFieldKind::Text => Self::Text,
            CoreFieldKind::Bytes => Self::Bytes,
            CoreFieldKind::Ipv4 => Self::Ipv4,
            CoreFieldKind::Ipv6 => Self::Ipv6,
            CoreFieldKind::Mac => Self::Mac,
            CoreFieldKind::List => Self::List,
            // v1 pins this value set; new kinds require a schema revision and explicit arm.
            _ => unreachable!("field kind {value:?} has no v1 output representation"),
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

impl From<&FieldSchema> for Field {
    fn from(value: &FieldSchema) -> Self {
        Self {
            name: value.name.to_owned(),
            kind: value.kind.into(),
            required: value.required,
            derived: value.derived,
            description: value.description.to_owned(),
        }
    }
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
}

impl Detail {
    pub fn new(summary: Summary, fields: Vec<Field>) -> Self {
        Self {
            protocol: summary.protocol,
            aliases: summary.aliases,
            build: summary.build,
            dissect: summary.dissect,
            exact_round_trip: summary.exact_round_trip,
            matcher: summary.matcher,
            decode_only: summary.decode_only,
            fields,
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
