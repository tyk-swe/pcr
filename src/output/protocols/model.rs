use serde::Serialize;

use crate::packet::field;
use crate::protocol::support;

/// Capability summary for one built-in protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProtocolSummary {
    pub protocol: String,
    pub aliases: Vec<String>,
    pub build: bool,
    pub dissect: bool,
    pub exact_round_trip: bool,
    pub matcher: bool,
    pub decode_only: bool,
}

impl From<&support::Protocol> for ProtocolSummary {
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
pub enum ProtocolFieldKind {
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

impl ProtocolFieldKind {
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

impl From<field::Kind> for ProtocolFieldKind {
    fn from(value: field::Kind) -> Self {
        match value {
            field::Kind::Bool => Self::Bool,
            field::Kind::Unsigned => Self::Unsigned,
            field::Kind::Signed => Self::Signed,
            field::Kind::Text => Self::Text,
            field::Kind::Bytes => Self::Bytes,
            field::Kind::Ipv4 => Self::Ipv4,
            field::Kind::Ipv6 => Self::Ipv6,
            field::Kind::Mac => Self::Mac,
            field::Kind::List => Self::List,
        }
    }
}

/// One ordered reflective field exposed by a built-in protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProtocolField {
    pub name: String,
    pub kind: ProtocolFieldKind,
    pub required: bool,
    pub derived: bool,
    pub description: String,
}

impl From<&field::Schema> for ProtocolField {
    fn from(value: &field::Schema) -> Self {
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
pub struct ProtocolDetail {
    pub protocol: String,
    pub aliases: Vec<String>,
    pub build: bool,
    pub dissect: bool,
    pub exact_round_trip: bool,
    pub matcher: bool,
    pub decode_only: bool,
    pub fields: Vec<ProtocolField>,
}

impl ProtocolDetail {
    pub fn new(summary: ProtocolSummary, fields: Vec<ProtocolField>) -> Self {
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
pub struct ProtocolListResult {
    pub protocols: Vec<ProtocolSummary>,
}

/// Aggregate result of describing one built-in protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProtocolDetailResult {
    pub protocol: ProtocolDetail,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn summaries_copy_every_manifest_capability_in_order() {
        let result = ProtocolListResult {
            protocols: support::BUILTIN_PROTOCOLS
                .iter()
                .map(ProtocolSummary::from)
                .collect(),
        };

        assert_eq!(result.protocols.len(), support::BUILTIN_PROTOCOLS.len());
        for (actual, expected) in result.protocols.iter().zip(support::BUILTIN_PROTOCOLS) {
            assert_eq!(actual.protocol, expected.protocol);
            assert_eq!(actual.aliases, expected.aliases.to_vec());
            assert_eq!(actual.build, expected.build);
            assert_eq!(actual.dissect, expected.dissect);
            assert_eq!(actual.exact_round_trip, expected.exact_round_trip);
            assert_eq!(actual.matcher, expected.matcher);
            assert_eq!(actual.decode_only, expected.decode_only);
        }
    }

    #[test]
    fn details_copy_every_constructible_reflective_field_exactly() {
        let registry = crate::protocol::builtin::registry().unwrap();

        for support in support::BUILTIN_PROTOCOLS {
            if support.decode_only {
                let detail = ProtocolDetail::new(ProtocolSummary::from(support), Vec::new());
                assert_eq!(detail.protocol, "raw_ip");
                assert!(detail.fields.is_empty());
                continue;
            }

            let layer = registry
                .codec(support.protocol)
                .unwrap()
                .make_layer(&BTreeMap::new())
                .unwrap();
            let fields = layer
                .schema()
                .fields
                .iter()
                .map(ProtocolField::from)
                .collect::<Vec<_>>();
            assert_eq!(
                fields.len(),
                layer.schema().fields.len(),
                "{}",
                support.protocol
            );
            for (actual, expected) in fields.iter().zip(layer.schema().fields) {
                assert_eq!(actual.name, expected.name, "{}", support.protocol);
                assert_eq!(actual.kind, expected.kind.into(), "{}", support.protocol);
                assert_eq!(actual.required, expected.required, "{}", support.protocol);
                assert_eq!(actual.derived, expected.derived, "{}", support.protocol);
                assert_eq!(
                    actual.description, expected.description,
                    "{}",
                    support.protocol
                );
            }
        }
    }
}
