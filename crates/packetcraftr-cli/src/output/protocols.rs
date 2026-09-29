// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use packetcraftr_core::field;
use packetcraftr_core::layer::FieldSchema;
use packetcraftr_core::protocol::BuiltinProtocol;
use packetcraftr_core::registry::{FilterFieldBinding, Registry};

use super::contract::Error;

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Binding {
    pub parent: String,
    pub discriminator: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterKind {
    Direct,
    Either,
    Bits,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FilterField {
    pub path: String,
    pub kind: FilterKind,
    pub fields: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shift: Option<u32>,
    pub description: String,
}

impl TryFrom<(&str, &FilterFieldBinding)> for FilterField {
    type Error = Error;

    fn try_from((path, binding): (&str, &FilterFieldBinding)) -> Result<Self, Error> {
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
            _ => {
                return Err(Error::Unpublished {
                    value: "filter field binding",
                });
            }
        };
        Ok(Self {
            path: path.to_owned(),
            kind,
            fields,
            mask,
            shift,
            description,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Detail {
    #[serde(flatten)]
    pub summary: Summary,
    pub fields: Vec<Field>,
    pub bindings: Vec<Binding>,
    pub filter_fields: Vec<FilterField>,
}

impl TryFrom<(&Registry, BuiltinProtocol)> for Detail {
    type Error = Error;

    fn try_from((registry, protocol): (&Registry, BuiltinProtocol)) -> Result<Self, Error> {
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
        let filter_fields = registry
            .filter_fields()
            .filter(|(_, binding)| binding.protocol().as_str() == protocol.as_str())
            .map(FilterField::try_from)
            .collect::<Result<_, _>>()?;
        Ok(Self {
            summary: Summary::from(protocol),
            fields,
            bindings,
            filter_fields,
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
