// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use packetcraftr_core::field;
use packetcraftr_core::layer::FieldSchema;
use packetcraftr_core::protocol::BuiltinProtocol;
use packetcraftr_core::registry::{FilterFieldBinding, Registry};

use super::contract::Error;

/// The reflective kind of a protocol field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum FieldKind {
    #[serde(rename = "bool")]
    Bool,
    #[serde(rename = "unsigned")]
    Unsigned,
    #[serde(rename = "signed")]
    Signed,
    #[serde(rename = "text")]
    Text,
    #[serde(rename = "bytes")]
    Bytes,
    #[serde(rename = "ipv4")]
    Ipv4,
    #[serde(rename = "ipv6")]
    Ipv6,
    #[serde(rename = "mac")]
    Mac,
    #[serde(rename = "list")]
    List,
    #[serde(rename = "object")]
    Object,
}

impl FieldKind {
    /// The published name, for text output that must agree with JSON.
    #[must_use]
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
            Self::Object => "object",
        }
    }
}

impl std::fmt::Display for FieldKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<field::FieldKind> for FieldKind {
    type Error = Error;

    fn try_from(value: field::FieldKind) -> Result<Self, Error> {
        Ok(match value {
            field::FieldKind::Bool => Self::Bool,
            field::FieldKind::Unsigned => Self::Unsigned,
            field::FieldKind::Signed => Self::Signed,
            field::FieldKind::Text => Self::Text,
            field::FieldKind::Bytes => Self::Bytes,
            field::FieldKind::Ipv4 => Self::Ipv4,
            field::FieldKind::Ipv6 => Self::Ipv6,
            field::FieldKind::Mac => Self::Mac,
            field::FieldKind::List => Self::List,
            field::FieldKind::Object => Self::Object,
            _ => {
                return Err(Error::Unpublished {
                    value: "protocol field kind",
                });
            }
        })
    }
}

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

impl From<BuiltinProtocol> for Summary {
    fn from(protocol: BuiltinProtocol) -> Self {
        Self {
            protocol: protocol.as_str().to_owned(),
            aliases: protocol
                .aliases()
                .iter()
                .map(|alias| (*alias).to_owned())
                .collect(),
            build: protocol.is_constructible(),
            dissect: true,
            exact_round_trip: protocol.exact_round_trip(),
            matcher: protocol.has_matcher(),
            decode_only: !protocol.is_constructible(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Field {
    pub name: String,
    pub kind: FieldKind,
    pub required: bool,
    pub derived: bool,
    pub description: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<Self>,
    /// JSON Pointer to a previously described child array within this top-level field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children_reference: Option<String>,
}

impl TryFrom<&FieldSchema> for Field {
    type Error = Error;

    fn try_from(value: &FieldSchema) -> Result<Self, Error> {
        Self::describe(value, "", &mut std::collections::HashMap::new())
    }
}
impl Field {
    fn describe(
        value: &FieldSchema,
        path: &str,
        seen: &mut std::collections::HashMap<(*const FieldSchema, usize), String>,
    ) -> Result<Self, Error> {
        let mut children_reference = None;
        let children = if value.children.is_empty() {
            Vec::new()
        } else {
            let key = (value.children.as_ptr(), value.children.len());
            if let Some(previous) = seen.get(&key) {
                children_reference = Some(previous.clone());
                Vec::new()
            } else {
                seen.insert(key, format!("{path}/children"));
                value
                    .children
                    .iter()
                    .enumerate()
                    .map(|(index, child)| {
                        Self::describe(child, &format!("{path}/children/{index}"), seen)
                    })
                    .collect::<Result<_, _>>()?
            }
        };
        Ok(Self {
            name: value.name.to_owned(),
            kind: value.kind.try_into()?,
            required: value.required,
            derived: value.derived,
            description: value.description.to_owned(),
            children,
            children_reference,
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

/// How a registered filter spelling reads its reflective fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterKind {
    Direct,
    Either,
    Bits,
}

/// One registered display-filter spelling, separate from dissection bindings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FilterField {
    pub path: String,
    pub kind: FilterKind,
    /// Canonical protocol-qualified fields read by this spelling.
    pub fields: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shift: Option<u32>,
    pub description: String,
}

impl FilterField {
    /// Every describable stored spelling that reads `protocol`, in path order.
    pub fn for_protocol(registry: &Registry, protocol: &str) -> Vec<Self> {
        registry
            .filter_fields()
            .filter(|(_, binding)| binding.protocol().as_str() == protocol)
            .filter_map(|(path, binding)| Self::from_binding(path, binding))
            .collect()
    }

    /// Describes a registry binding known to the output contract.
    /// Future binding kinds may omit this optional discovery metadata.
    pub fn from_binding(path: &str, binding: &FilterFieldBinding) -> Option<Self> {
        let fields: Vec<_> = binding
            .fields()
            .iter()
            .map(|field| format!("{}.{}", binding.protocol(), field))
            .collect();
        let (kind, mask, shift, description) = match binding {
            FilterFieldBinding::Direct { protocol, field } => (
                FilterKind::Direct,
                None,
                None,
                format!("Alias for {protocol}.{field}."),
            ),
            FilterFieldBinding::Either { .. } => (
                FilterKind::Either,
                None,
                None,
                format!(
                    "Comparison matches when any of [{}] satisfies it; != matches when any listed field differs, even if another equals the value.",
                    fields.join(", ")
                ),
            ),
            FilterFieldBinding::Bits {
                protocol,
                field,
                mask,
                shift,
            } => (
                FilterKind::Bits,
                Some(*mask),
                Some(*shift),
                format!("Reads ({protocol}.{field} & {mask}) >> {shift} before comparison."),
            ),
            _ => return None,
        };
        Some(Self {
            path: path.to_owned(),
            kind,
            fields,
            mask,
            shift,
            description,
        })
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
    pub bindings: Vec<Binding>,
    pub filter_fields: Vec<FilterField>,
}

/// A built-in protocol described from the registry: its capabilities,
/// reflective fields, the parents that reach it, and its filter spellings.
impl TryFrom<(&Registry, BuiltinProtocol)> for Detail {
    type Error = Error;

    fn try_from((registry, protocol): (&Registry, BuiltinProtocol)) -> Result<Self, Error> {
        let summary = Summary::from(protocol);
        let fields = registry
            .schema(protocol.as_str())
            .map(|schema| {
                schema
                    .fields
                    .iter()
                    .map(Field::try_from)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        let bindings = registry
            .parent_bindings(protocol.as_str())
            .into_iter()
            .map(|(parent, discriminator)| Binding {
                parent: parent.as_str().to_owned(),
                discriminator: discriminator.0,
            })
            .collect();
        Ok(Self {
            protocol: summary.protocol,
            aliases: summary.aliases,
            build: summary.build,
            dissect: summary.dissect,
            exact_round_trip: summary.exact_round_trip,
            matcher: summary.matcher,
            decode_only: summary.decode_only,
            fields,
            bindings,
            filter_fields: FilterField::for_protocol(registry, protocol.as_str()),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ListResult {
    pub protocols: Vec<Summary>,
}

impl From<&[BuiltinProtocol]> for ListResult {
    fn from(protocols: &[BuiltinProtocol]) -> Self {
        Self {
            protocols: protocols.iter().copied().map(Summary::from).collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DetailResult {
    pub protocol: Detail,
}

impl From<Detail> for DetailResult {
    fn from(protocol: Detail) -> Self {
        Self { protocol }
    }
}
