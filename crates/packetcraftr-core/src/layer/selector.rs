// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Layer-field selectors.
//!
//! A selector names one field of one layer in a packet. It is either
//! `<protocol>[#occurrence].<field>`, where the occurrence counts layers of
//! that protocol from one, outermost first, or the zero-based `LAYER.FIELD`
//! that predates it. A `*` in place of the protocol or the field selects every
//! layer or every readable field, for the callers that allow it.
//!
//! Selectors are resolved against a concrete packet once, up front. Everything
//! downstream, including published reproduction data, keeps using numeric layer
//! indexes.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;

use crate::error::{Classification, Classified, Kind};
use crate::field::Path;
use crate::packet::Packet;
use crate::registry::Registry;

/// Matches every layer, or every readable field of a layer.
pub const WILDCARD: &str = "*";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LayerSelector {
    /// A zero-based position in the packet.
    Index(usize),
    /// The `occurrence`th layer of a protocol, counting from one.
    Protocol { name: String, occurrence: usize },
    /// Every layer.
    Any,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selector {
    layer: LayerSelector,
    field: String,
}

impl Selector {
    #[must_use]
    pub fn layer(&self) -> &LayerSelector {
        &self.layer
    }

    /// The field path, lowercased like the protocol name so every consumer
    /// reads the grammar the same way, or [`WILDCARD`].
    #[must_use]
    pub fn field(&self) -> &str {
        &self.field
    }

    #[must_use]
    pub fn has_wildcard(&self) -> bool {
        self.layer == LayerSelector::Any || self.field == WILDCARD
    }

    /// The zero-based layer index this selector names.
    ///
    /// A numeric index is returned as written without checking it against the
    /// packet, so the caller reports an out-of-range layer in its own terms.
    ///
    /// # Errors
    ///
    /// [`Error::Wildcard`] for a layer wildcard, [`Error::UnknownProtocol`]
    /// for a protocol the registry does not know, and
    /// [`Error::OccurrenceOutOfRange`] when the packet has fewer layers of the
    /// protocol than the occurrence asks for.
    pub fn resolve_layer(&self, packet: &Packet, registry: &Registry) -> Result<usize, Error> {
        match &self.layer {
            LayerSelector::Index(index) => Ok(*index),
            LayerSelector::Any => Err(Error::Wildcard {
                selector: self.to_string(),
            }),
            LayerSelector::Protocol { name, occurrence } => {
                let protocol = registry
                    .protocol_named(name)
                    .ok_or_else(|| Error::UnknownProtocol { name: name.clone() })?;
                let mut found = 0_usize;
                for (index, layer) in packet.iter().enumerate() {
                    if *layer.protocol_id() != protocol {
                        continue;
                    }
                    found += 1;
                    if found == *occurrence {
                        return Ok(index);
                    }
                }
                Err(Error::OccurrenceOutOfRange {
                    protocol: name.clone(),
                    occurrence: *occurrence,
                    found,
                })
            }
        }
    }

    /// Every `(layer index, field)` pair the selector names, in layer then
    /// schema order, never more than `limit`.
    ///
    /// A field without a wildcard is returned as parsed, so a numeric
    /// `LAYER.FIELD` expands to itself and field validity stays with the
    /// consumer. A field wildcard expands to the layer's readable schema
    /// fields, and a layer wildcard keeps the layers that have the field.
    ///
    /// # Errors
    ///
    /// The errors of [`resolve_layer`](Self::resolve_layer), plus
    /// [`Error::LayerOutOfRange`] when a field wildcard names a missing layer,
    /// [`Error::NoMatch`] when nothing matches, and [`Error::TooManyTargets`]
    /// beyond `limit`.
    pub fn expand(
        &self,
        packet: &Packet,
        registry: &Registry,
        limit: usize,
    ) -> Result<Vec<(usize, String)>, Error> {
        let layers: Vec<usize> = match self.layer {
            LayerSelector::Any => (0..packet.len()).collect(),
            _ => vec![self.resolve_layer(packet, registry)?],
        };
        let wildcard_layers = self.layer == LayerSelector::Any;
        let mut targets = Vec::new();
        let mut push = |layer: usize, field: &str| {
            if targets.len() >= limit {
                return Err(Error::TooManyTargets { limit });
            }
            targets.push((layer, field.to_owned()));
            Ok(())
        };
        if self.field == WILDCARD {
            for index in layers {
                let layer = packet.layer(index).ok_or(Error::LayerOutOfRange {
                    index,
                    layers: packet.len(),
                })?;
                for field in layer.schema().fields {
                    if layer.field(field.name).is_some() {
                        push(index, field.name)?;
                    }
                }
            }
        } else if wildcard_layers {
            let path = self.field.parse::<Path>().map_err(|source| Error::Field {
                selector: self.to_string(),
                source,
            })?;
            for index in layers {
                let Some(layer) = packet.layer(index) else {
                    continue;
                };
                if path.schema(layer.schema()).is_some() {
                    push(index, &self.field)?;
                }
            }
        } else {
            push(layers[0], &self.field)?;
        }
        if targets.is_empty() {
            return Err(Error::NoMatch {
                selector: self.to_string(),
            });
        }
        Ok(targets)
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.layer {
            LayerSelector::Index(index) => write!(formatter, "{index}")?,
            LayerSelector::Protocol {
                name,
                occurrence: 1,
            } => formatter.write_str(name)?,
            LayerSelector::Protocol { name, occurrence } => {
                write!(formatter, "{name}#{occurrence}")?;
            }
            LayerSelector::Any => formatter.write_str(WILDCARD)?,
        }
        write!(formatter, ".{}", self.field)
    }
}

impl FromStr for Selector {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        let syntax = || Error::Syntax {
            selector: text.chars().take(256).collect(),
        };
        let text = text.trim();
        let (head, field) = text.split_once('.').ok_or_else(syntax)?;
        let field = field.trim();
        if head.is_empty() || field.is_empty() || head.contains(char::is_whitespace) {
            return Err(syntax());
        }
        let layer = if head == WILDCARD {
            LayerSelector::Any
        } else if head.bytes().all(|byte| byte.is_ascii_digit()) {
            LayerSelector::Index(head.parse().map_err(|_| syntax())?)
        } else {
            let (name, occurrence) = split_occurrence(head).map_err(|fault| Error::Occurrence {
                selector: text.to_owned(),
                fault,
            })?;
            if name == WILDCARD {
                return Err(syntax());
            }
            LayerSelector::Protocol {
                name: name.to_ascii_lowercase(),
                occurrence,
            }
        };
        Ok(Self {
            layer,
            field: field.to_ascii_lowercase(),
        })
    }
}

/// How a `#occurrence` suffix was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OccurrenceFault {
    /// An empty protocol name or more than one `#`.
    Malformed,
    NotNumber,
    /// Occurrences start at one.
    Zero,
}

impl fmt::Display for OccurrenceFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "expected <protocol>#<occurrence>",
            Self::NotNumber => "the occurrence is not a number",
            Self::Zero => "occurrences start at 1",
        })
    }
}

/// Splits `<protocol>[#occurrence]`; the occurrence defaults to one.
pub(crate) fn split_occurrence(head: &str) -> Result<(&str, usize), OccurrenceFault> {
    let Some((name, digits)) = head.split_once('#') else {
        return Ok((head, 1));
    };
    if name.is_empty() || digits.contains('#') {
        return Err(OccurrenceFault::Malformed);
    }
    let occurrence: usize = digits.parse().map_err(|_| OccurrenceFault::NotNumber)?;
    if occurrence == 0 {
        return Err(OccurrenceFault::Zero);
    }
    Ok((name, occurrence))
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("selector {selector:?} must be <protocol>[#occurrence].<field> or LAYER.FIELD")]
    Syntax { selector: String },
    #[error("selector {selector:?} has an invalid layer occurrence: {fault}")]
    Occurrence {
        selector: String,
        fault: OccurrenceFault,
    },
    #[error("selector {selector:?} uses a wildcard where one layer and field are required")]
    Wildcard { selector: String },
    #[error("selector names unknown protocol {name:?}")]
    UnknownProtocol { name: String },
    #[error("selector layer index {index} is outside the packet's {layers} layers")]
    LayerOutOfRange { index: usize, layers: usize },
    #[error("selector asks for occurrence {occurrence} of {protocol}, but the packet has {found}")]
    OccurrenceOutOfRange {
        protocol: String,
        occurrence: usize,
        found: usize,
    },
    #[error("selector {selector:?} matches no layer field in the packet")]
    NoMatch { selector: String },
    #[error("selectors name more than {limit} fields")]
    TooManyTargets { limit: usize },
    #[error("selector {selector:?} does not end in a bounded reflective field path")]
    Field {
        selector: String,
        #[source]
        source: crate::field::Error,
    },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        Classification::new(
            "cli.selector",
            Kind::Usage,
            Some(
                "select a field as <protocol>[#occurrence].<field>, for example ipv4#2.ttl, or as a zero-based LAYER.FIELD",
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet() -> Packet {
        // vlan / ipv4 / udp / ipv4 / tcp
        crate::expression::parse(
            "vlan(vlan_id=7)/ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(dport=4789)/ipv4(src=198.51.100.1,dst=198.51.100.2)/tcp()",
            &crate::protocol::builtin::registry(),
            crate::expression::Limits::default(),
        )
        .expect("fixture packet")
    }

    fn select(text: &str) -> Selector {
        text.parse()
            .unwrap_or_else(|error| panic!("{text}: {error}"))
    }

    #[test]
    fn selectors_parse_names_occurrences_indexes_and_wildcards() {
        for (text, layer, field) in [
            (
                "ipv4.ttl",
                LayerSelector::Protocol {
                    name: "ipv4".to_owned(),
                    occurrence: 1,
                },
                "ttl",
            ),
            (
                " IPv4#2.ttl ",
                LayerSelector::Protocol {
                    name: "ipv4".to_owned(),
                    occurrence: 2,
                },
                "ttl",
            ),
            ("0.ttl", LayerSelector::Index(0), "ttl"),
            ("0.TTL", LayerSelector::Index(0), "ttl"),
            (
                "12.questions[0].name",
                LayerSelector::Index(12),
                "questions[0].name",
            ),
            ("*.ttl", LayerSelector::Any, "ttl"),
            (
                "tcp.*",
                LayerSelector::Protocol {
                    name: "tcp".to_owned(),
                    occurrence: 1,
                },
                "*",
            ),
        ] {
            let selector = select(text);
            assert_eq!(selector.layer(), &layer, "{text}");
            assert_eq!(selector.field(), field, "{text}");
        }
        assert_eq!(select("ipv4#2.ttl").to_string(), "ipv4#2.ttl");
        assert_eq!(select("ipv4#1.ttl").to_string(), "ipv4.ttl");
        assert!(select("*.*").has_wildcard());
        assert!(!select("ipv4.ttl").has_wildcard());
    }

    #[test]
    fn malformed_selectors_are_typed_syntax_errors() {
        for text in [
            "",
            "ttl",
            ".ttl",
            "ipv4.",
            "ipv4 .ttl",
            "*#2.ttl",
            "99999999999999999999999.ttl",
        ] {
            assert!(
                matches!(text.parse::<Selector>(), Err(Error::Syntax { .. })),
                "{text:?}"
            );
        }
        for (text, expected) in [
            ("ipv4#0.ttl", OccurrenceFault::Zero),
            ("ipv4#x.ttl", OccurrenceFault::NotNumber),
            ("ipv4#.ttl", OccurrenceFault::NotNumber),
            ("#2.ttl", OccurrenceFault::Malformed),
            ("ipv4#1#2.ttl", OccurrenceFault::Malformed),
        ] {
            assert!(
                matches!(text.parse::<Selector>(), Err(Error::Occurrence { fault, .. }) if fault == expected),
                "{text:?}"
            );
        }
    }

    #[test]
    fn occurrences_count_matching_layers_from_the_outermost() {
        let (packet, registry) = (packet(), crate::protocol::builtin::registry());
        let layer = |text: &str| select(text).resolve_layer(&packet, &registry);
        assert_eq!(layer("vlan.priority").unwrap(), 0);
        assert_eq!(layer("ipv4.ttl").unwrap(), 1);
        assert_eq!(layer("ipv4#2.ttl").unwrap(), 3);
        assert_eq!(layer("ip#2.ttl").unwrap(), 3, "aliases resolve");
        assert_eq!(layer("tcp.flags").unwrap(), 4);
        // numeric indexes pass through unchecked
        assert_eq!(layer("9.ttl").unwrap(), 9);

        assert!(matches!(
            layer("ipv4#3.ttl"),
            Err(Error::OccurrenceOutOfRange {
                occurrence: 3,
                found: 2,
                ..
            })
        ));
        assert!(matches!(
            layer("dns.id"),
            Err(Error::OccurrenceOutOfRange { found: 0, .. })
        ));
        assert!(matches!(
            layer("nosuchprotocol.x"),
            Err(Error::UnknownProtocol { .. })
        ));
        assert!(matches!(layer("*.ttl"), Err(Error::Wildcard { .. })));
        assert_eq!(
            layer("ipv4#3.ttl").unwrap_err().classification().code,
            "cli.selector"
        );
    }

    #[test]
    fn expansion_covers_wildcards_and_respects_the_limit() {
        let (packet, registry) = (packet(), crate::protocol::builtin::registry());
        let expand = |text: &str, limit| select(text).expand(&packet, &registry, limit);

        assert_eq!(expand("ipv4#2.ttl", 8).unwrap(), [(3, "ttl".to_owned())]);
        assert_eq!(
            expand("*.ttl", 8).unwrap(),
            [(1, "ttl".to_owned()), (3, "ttl".to_owned())]
        );
        assert_eq!(
            expand("udp.*", 64)
                .unwrap()
                .iter()
                .map(|(layer, _)| *layer)
                .collect::<Vec<_>>(),
            vec![2; expand("udp.*", 64).unwrap().len()]
        );
        assert!(expand("udp.*", 64).unwrap().len() > 2);
        // a numeric layer with a field wildcard still checks the layer exists
        assert!(matches!(
            expand("9.*", 64),
            Err(Error::LayerOutOfRange {
                index: 9,
                layers: 5
            })
        ));
        assert!(matches!(
            expand("*.*", 3),
            Err(Error::TooManyTargets { limit: 3 })
        ));
        assert!(matches!(
            expand("*.nosuchfield", 8),
            Err(Error::NoMatch { .. })
        ));
        assert!(matches!(expand("*.a[", 8), Err(Error::Field { .. })));
        // an exact numeric selector expands to itself without field validation
        assert_eq!(
            expand("0.whatever", 1).unwrap(),
            [(0, "whatever".to_owned())]
        );
    }
}
