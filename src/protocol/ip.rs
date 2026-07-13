// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use bytes::Bytes;
use thiserror::Error;

use crate::packet::internal::{
    CodecError, DecodedLayerValue, Diagnostic, Discriminator, EncodedLayer, FieldError, FieldKind,
    FieldSchema, FieldValue, Layer, LayerCodec, LayerDecodeContext, LayerEncodeContext,
    LayerSchema, NetworkEnvelope, ProtocolId, WireValue,
};

use super::common::{
    aliased_fields, binding_protocol, bytes, checksum, field_layout, impl_layer_boilerplate,
    invalid, ipv4, ipv6, make_layer, network_from_addresses, out_of_range, payload_without_padding,
    protocol, resolve_u16, resolve_u8, set_wire_u16, set_wire_u8, strict_or_diagnostic, truncated,
    unknown_field, validate_auto_raw_discriminator, validate_ipv6_routing_child,
    validate_raw_child_discriminator, wire_u16, wire_u8, wrong_layer, wrong_type,
};

const IPV4_MIN_LEN: usize = 20;
const IPV6_LEN: usize = 40;

fn is_ipv6_extension_layer(layer: &dyn Layer) -> bool {
    matches!(
        layer.protocol_id().as_str(),
        "ipv6_hop_by_hop" | "ipv6_destination_options" | "ipv6_fragment" | "ipv6_srh"
    )
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("invalid IPv4 options: {reason}")]
pub(crate) struct Ipv4OptionsError {
    reason: String,
}

fn invalid_ipv4_options(reason: impl Into<String>) -> Ipv4OptionsError {
    Ipv4OptionsError {
        reason: reason.into(),
    }
}

/// Returns every address carried by Loose or Strict Source Route. All live
/// paths use this parser so malformed route-affecting options fail closed.
pub(crate) fn ipv4_source_route_destinations(
    options: &[u8],
) -> Result<Vec<Ipv4Addr>, Ipv4OptionsError> {
    if options.len() > 40 {
        return Err(invalid_ipv4_options(
            "option bytes exceed the 40-byte header limit",
        ));
    }
    let mut destinations = Vec::new();
    let mut cursor = 0usize;
    while cursor < options.len() {
        match options[cursor] {
            0 => break,
            1 => cursor += 1,
            option => {
                let length = options
                    .get(cursor + 1)
                    .copied()
                    .map(usize::from)
                    .ok_or_else(|| invalid_ipv4_options("option is missing its length byte"))?;
                if length < 2 {
                    return Err(invalid_ipv4_options(format!(
                        "option {option} has invalid length {length}"
                    )));
                }
                let end = cursor
                    .checked_add(length)
                    .filter(|end| *end <= options.len())
                    .ok_or_else(|| invalid_ipv4_options(format!("option {option} is truncated")))?;
                if matches!(option, 131 | 137) {
                    if length < 3 || !(length - 3).is_multiple_of(4) {
                        return Err(invalid_ipv4_options(format!(
                            "source-route option {option} has invalid length {length}"
                        )));
                    }
                    let pointer = usize::from(options[cursor + 2]);
                    if pointer < 4 || pointer > length + 1 || !(pointer - 4).is_multiple_of(4) {
                        return Err(invalid_ipv4_options(format!(
                            "source-route option {option} has invalid pointer {pointer}"
                        )));
                    }
                    for address in options[cursor + 3..end].chunks_exact(4) {
                        destinations.push(Ipv4Addr::new(
                            address[0], address[1], address[2], address[3],
                        ));
                    }
                }
                cursor = end;
            }
        }
    }
    Ok(destinations)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv4 {
    pub dscp_ecn: u8,
    pub total_length: WireValue<u16>,
    pub identification: u16,
    pub reserved_flag: bool,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: WireValue<u8>,
    pub checksum: WireValue<u16>,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub options: Bytes,
}

impl Default for Ipv4 {
    fn default() -> Self {
        Self {
            dscp_ecn: 0,
            total_length: WireValue::Auto,
            identification: 0,
            reserved_flag: false,
            dont_fragment: false,
            more_fragments: false,
            fragment_offset: 0,
            ttl: 64,
            protocol: WireValue::Auto,
            checksum: WireValue::Auto,
            source: Ipv4Addr::UNSPECIFIED,
            destination: Ipv4Addr::UNSPECIFIED,
            options: Bytes::new(),
        }
    }
}

fn ipv4_schema() -> &'static LayerSchema {
    static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
    static FIELDS: &[FieldSchema] = &[
        FieldSchema {
            name: "dscp_ecn",
            kind: FieldKind::Unsigned,
            derived: false,
            required: false,
            description: "DSCP and ECN octet",
        },
        FieldSchema {
            name: "total_length",
            kind: FieldKind::Unsigned,
            derived: true,
            required: false,
            description: "IPv4 total length",
        },
        FieldSchema {
            name: "identification",
            kind: FieldKind::Unsigned,
            derived: false,
            required: false,
            description: "Fragment identification",
        },
        FieldSchema {
            name: "reserved_flag",
            kind: FieldKind::Bool,
            derived: false,
            required: false,
            description: "Reserved IPv4 flag bit",
        },
        FieldSchema {
            name: "dont_fragment",
            kind: FieldKind::Bool,
            derived: false,
            required: false,
            description: "Don't-fragment flag",
        },
        FieldSchema {
            name: "more_fragments",
            kind: FieldKind::Bool,
            derived: false,
            required: false,
            description: "More-fragments flag",
        },
        FieldSchema {
            name: "fragment_offset",
            kind: FieldKind::Unsigned,
            derived: false,
            required: false,
            description: "Fragment offset in eight-byte units",
        },
        FieldSchema {
            name: "ttl",
            kind: FieldKind::Unsigned,
            derived: false,
            required: true,
            description: "Time to live",
        },
        FieldSchema {
            name: "protocol",
            kind: FieldKind::Unsigned,
            derived: true,
            required: false,
            description: "Next protocol discriminator",
        },
        FieldSchema {
            name: "checksum",
            kind: FieldKind::Unsigned,
            derived: true,
            required: false,
            description: "IPv4 header checksum",
        },
        FieldSchema {
            name: "source",
            kind: FieldKind::Ipv4,
            derived: false,
            required: true,
            description: "Source IPv4 address",
        },
        FieldSchema {
            name: "destination",
            kind: FieldKind::Ipv4,
            derived: false,
            required: true,
            description: "Destination IPv4 address",
        },
        FieldSchema {
            name: "options",
            kind: FieldKind::Bytes,
            derived: false,
            required: false,
            description: "Verbatim IPv4 option bytes",
        },
    ];
    SCHEMA.get_or_init(|| LayerSchema {
        protocol: protocol("ipv4"),
        name: "IPv4",
        fields: FIELDS,
    })
}

impl Layer for Ipv4 {
    impl_layer_boilerplate!(Ipv4, ipv4_schema);

    fn field(&self, name: &str) -> Option<FieldValue> {
        match name {
            "dscp_ecn" => Some(self.dscp_ecn.into()),
            "total_length" => Some(wire_u16(&self.total_length)),
            "identification" => Some(self.identification.into()),
            "reserved_flag" => Some(self.reserved_flag.into()),
            "dont_fragment" => Some(self.dont_fragment.into()),
            "more_fragments" => Some(self.more_fragments.into()),
            "fragment_offset" => Some(self.fragment_offset.into()),
            "ttl" => Some(self.ttl.into()),
            "protocol" => Some(wire_u8(&self.protocol)),
            "checksum" => Some(wire_u16(&self.checksum)),
            "source" => Some(self.source.into()),
            "destination" => Some(self.destination.into()),
            "options" => Some(self.options.clone().into()),
            _ => None,
        }
    }

    fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), FieldError> {
        match (name, value) {
            ("dscp_ecn", FieldValue::Unsigned(value)) => {
                self.dscp_ecn =
                    u8::try_from(value).map_err(|_| out_of_range(ipv4_schema(), name))?
            }
            ("total_length", value) => {
                return set_wire_u16(&mut self.total_length, ipv4_schema(), name, value)
            }
            ("identification", FieldValue::Unsigned(value)) => {
                self.identification =
                    u16::try_from(value).map_err(|_| out_of_range(ipv4_schema(), name))?
            }
            ("reserved_flag", FieldValue::Bool(value)) => self.reserved_flag = value,
            ("dont_fragment", FieldValue::Bool(value)) => self.dont_fragment = value,
            ("more_fragments", FieldValue::Bool(value)) => self.more_fragments = value,
            ("fragment_offset", FieldValue::Unsigned(value)) => {
                self.fragment_offset = u16::try_from(value)
                    .ok()
                    .filter(|value| *value <= 0x1fff)
                    .ok_or_else(|| out_of_range(ipv4_schema(), name))?
            }
            ("ttl", FieldValue::Unsigned(value)) => {
                self.ttl = u8::try_from(value).map_err(|_| out_of_range(ipv4_schema(), name))?
            }
            ("protocol", value) => {
                return set_wire_u8(&mut self.protocol, ipv4_schema(), name, value)
            }
            ("checksum", value) => {
                return set_wire_u16(&mut self.checksum, ipv4_schema(), name, value)
            }
            ("source", value) => {
                self.source = ipv4(&value).ok_or_else(|| wrong_type(ipv4_schema(), name, "ipv4"))?
            }
            ("destination", value) => {
                self.destination =
                    ipv4(&value).ok_or_else(|| wrong_type(ipv4_schema(), name, "ipv4"))?
            }
            ("options", value) => {
                self.options =
                    bytes(&value).ok_or_else(|| wrong_type(ipv4_schema(), name, "bytes"))?
            }
            ("reserved_flag" | "dont_fragment" | "more_fragments", _) => {
                return Err(wrong_type(ipv4_schema(), name, "bool"))
            }
            ("dscp_ecn" | "identification" | "fragment_offset" | "ttl", _) => {
                return Err(wrong_type(ipv4_schema(), name, "unsigned"))
            }
            _ => return Err(unknown_field(ipv4_schema(), name)),
        }
        Ok(())
    }

    fn normalize(&mut self) {
        self.total_length.normalize();
        self.protocol.normalize();
        self.checksum.normalize();
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Ipv4Codec;

impl LayerCodec for Ipv4Codec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("ipv4")
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["ip", "ip4"]
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Ipv4>()
            .ok_or_else(|| wrong_layer("ipv4", layer))?;
        if layer.fragment_offset > 0x1fff {
            return Err(invalid("ipv4", "fragment offset exceeds 13 bits"));
        }
        if layer.options.len() > 40 {
            return Err(invalid("ipv4", "options exceed the 40-byte IPv4 limit"));
        }

        let source = if layer.source.is_unspecified() {
            match context.build_context.source {
                Some(IpAddr::V4(source)) => source,
                _ => layer.source,
            }
        } else {
            layer.source
        };
        let destination = if layer.destination.is_unspecified() {
            match context.build_context.destination {
                Some(IpAddr::V4(destination)) => destination,
                _ => layer.destination,
            }
        } else {
            layer.destination
        };

        let mut diagnostics = Vec::new();
        if layer.reserved_flag {
            let message = "reserved IPv4 flag bit is set";
            if context.mode == crate::packet::internal::BuildMode::Strict {
                return Err(invalid("ipv4", message));
            }
            diagnostics.push(
                Diagnostic::warning("build.ipv4_reserved_flag", message).at_field("reserved_flag"),
            );
        }
        let mut options = layer.options.to_vec();
        let padding = (4 - (options.len() % 4)) % 4;
        if padding != 0 {
            options.resize(options.len() + padding, 0);
            diagnostics.push(
                Diagnostic::warning(
                    "build.ipv4_options_padded",
                    format!("padded IPv4 options with {padding} zero byte(s)"),
                )
                .at_field("options"),
            );
        }
        let header_len = IPV4_MIN_LEN + options.len();
        let covered_payload = payload_without_padding("ipv4", payload, context)?;
        if layer.dont_fragment && (layer.more_fragments || layer.fragment_offset != 0) {
            strict_or_diagnostic(
                "ipv4",
                "build.ipv4_conflicting_fragment_flags",
                "dont_fragment",
                "don't-fragment cannot be combined with MF or a non-zero fragment offset",
                context,
                &mut diagnostics,
            )?;
        }
        if layer.more_fragments && covered_payload.len() % 8 != 0 {
            strict_or_diagnostic(
                "ipv4",
                "build.ipv4_fragment_alignment",
                "more_fragments",
                format!(
                    "non-final fragment payload length {} is not a multiple of eight bytes",
                    covered_payload.len()
                ),
                context,
                &mut diagnostics,
            )?;
        }
        if (layer.fragment_offset != 0 || layer.more_fragments)
            && context.child.is_some_and(|child| {
                !matches!(
                    child.protocol_id().as_str(),
                    "raw" | "padding" | "malformed"
                )
            })
        {
            strict_or_diagnostic(
                "ipv4",
                "build.typed_fragment_payload",
                "fragment_offset",
                "fragment payload must be Raw; convert typed fragment payloads to Raw explicitly",
                context,
                &mut diagnostics,
            )?;
        }
        let total_expected = header_len
            .checked_add(covered_payload.len())
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| invalid("ipv4", "packet exceeds IPv4 total-length range"))?;
        let (total_length, materialized_total) = resolve_u16(
            "ipv4",
            "total_length",
            &layer.total_length,
            total_expected,
            true,
            context.mode,
            &mut diagnostics,
        )?;
        let (expected_protocol, validate_protocol) = expected_next("ipv4", context, 255);
        validate_auto_raw_discriminator(
            "ipv4",
            "protocol",
            matches!(layer.protocol, WireValue::Auto),
            context,
            &mut diagnostics,
        )?;
        let (next_protocol, materialized_protocol) = resolve_u8(
            "ipv4",
            "protocol",
            &layer.protocol,
            expected_protocol,
            validate_protocol,
            context.mode,
            &mut diagnostics,
        )?;
        if layer.fragment_offset == 0 && !layer.more_fragments {
            validate_raw_child_discriminator(
                "ipv4",
                u64::from(next_protocol),
                context,
                &mut diagnostics,
            )?;
        }

        let ihl =
            u8::try_from(header_len / 4).map_err(|_| invalid("ipv4", "header length overflow"))?;
        let mut prefix = vec![0u8; header_len];
        prefix[0] = (4 << 4) | ihl;
        prefix[1] = layer.dscp_ecn;
        prefix[2..4].copy_from_slice(&total_length.to_be_bytes());
        prefix[4..6].copy_from_slice(&layer.identification.to_be_bytes());
        let flags_offset = (if layer.reserved_flag { 1 << 15 } else { 0 })
            | (if layer.dont_fragment { 1 << 14 } else { 0 })
            | (if layer.more_fragments { 1 << 13 } else { 0 })
            | layer.fragment_offset;
        prefix[6..8].copy_from_slice(&flags_offset.to_be_bytes());
        prefix[8] = layer.ttl;
        prefix[9] = next_protocol;
        prefix[12..16].copy_from_slice(&source.octets());
        prefix[16..20].copy_from_slice(&destination.octets());
        prefix[20..].copy_from_slice(&options);
        let checksum_expected = checksum(&prefix);
        let (header_checksum, materialized_checksum) = resolve_u16(
            "ipv4",
            "checksum",
            &layer.checksum,
            checksum_expected,
            true,
            context.mode,
            &mut diagnostics,
        )?;
        prefix[10..12].copy_from_slice(&header_checksum.to_be_bytes());

        let mut materialized = layer.clone();
        materialized.total_length = materialized_total;
        materialized.protocol = materialized_protocol;
        materialized.checksum = materialized_checksum;
        materialized.source = source;
        materialized.destination = destination;
        materialized.options = Bytes::from(options);
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: ipv4_layout(header_len),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < IPV4_MIN_LEN {
            return Err(truncated("ipv4", IPV4_MIN_LEN, input.len()));
        }
        if input[0] >> 4 != 4 {
            return Err(invalid(
                "ipv4",
                format!("version is {}, not 4", input[0] >> 4),
            ));
        }
        let ihl = usize::from(input[0] & 0x0f);
        if ihl < 5 {
            return Err(invalid("ipv4", format!("IHL {ihl} is below 5")));
        }
        let header_len = ihl
            .checked_mul(4)
            .ok_or_else(|| invalid("ipv4", "IHL overflow"))?;
        if input.len() < header_len {
            return Err(truncated("ipv4", header_len, input.len()));
        }
        let total_length = usize::from(u16::from_be_bytes([input[2], input[3]]));
        if total_length < header_len {
            return Err(invalid(
                "ipv4",
                format!("total length {total_length} is smaller than header {header_len}"),
            ));
        }
        if input.len() < total_length {
            return Err(truncated("ipv4", total_length, input.len()));
        }
        let flags_offset = u16::from_be_bytes([input[6], input[7]]);
        let next = input[9];
        let source = Ipv4Addr::new(input[12], input[13], input[14], input[15]);
        let destination = Ipv4Addr::new(input[16], input[17], input[18], input[19]);
        let mut diagnostics = Vec::new();
        if context.verify_checksums && checksum(&input[..header_len]) != 0 {
            diagnostics.push(
                Diagnostic::warning("decode.ipv4_checksum", "IPv4 header checksum mismatch")
                    .at_field("checksum"),
            );
        }
        let fragment_offset = flags_offset & 0x1fff;
        if flags_offset & 0x8000 != 0 {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.ipv4_reserved_flag",
                    "reserved IPv4 flag bit is non-zero",
                )
                .at_field("reserved_flag"),
            );
        }
        let payload_len = total_length - header_len;
        Ok(DecodedLayerValue {
            layer: Box::new(Ipv4 {
                dscp_ecn: input[1],
                total_length: WireValue::Exact(total_length as u16),
                identification: u16::from_be_bytes([input[4], input[5]]),
                reserved_flag: (flags_offset & 0x8000) != 0,
                dont_fragment: (flags_offset & 0x4000) != 0,
                more_fragments: (flags_offset & 0x2000) != 0,
                fragment_offset,
                ttl: input[8],
                protocol: WireValue::Exact(next),
                checksum: WireValue::Exact(u16::from_be_bytes([input[10], input[11]])),
                source,
                destination,
                options: Bytes::copy_from_slice(&input[20..header_len]),
            }),
            consumed: header_len,
            payload_offset: header_len,
            payload_len,
            next: if fragment_offset == 0 && (flags_offset & 0x2000) == 0 {
                vec![Discriminator(u64::from(next))]
            } else {
                vec![Discriminator(255)]
            },
            fields: ipv4_layout(header_len),
            diagnostics,
            stop: payload_len == 0,
            network: Some(network_from_addresses(source.into(), destination.into())),
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(
            Ipv4::default(),
            &aliased_fields("ipv4", fields, &[("src", "source"), ("dst", "destination")])?,
        )
    }
}

fn ipv4_layout(header_len: usize) -> Vec<crate::packet::internal::FieldLayout> {
    vec![
        field_layout("dscp_ecn", 1, 2),
        field_layout("total_length", 2, 4),
        field_layout("identification", 4, 6),
        field_layout("reserved_flag", 6, 8),
        field_layout("dont_fragment", 6, 8),
        field_layout("more_fragments", 6, 8),
        field_layout("fragment_offset", 6, 8),
        field_layout("ttl", 8, 9),
        field_layout("protocol", 9, 10),
        field_layout("checksum", 10, 12),
        field_layout("source", 12, 16),
        field_layout("destination", 16, 20),
        field_layout("options", 20, header_len),
    ]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv6 {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: WireValue<u16>,
    pub next_header: WireValue<u8>,
    pub hop_limit: u8,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
}

impl Default for Ipv6 {
    fn default() -> Self {
        Self {
            traffic_class: 0,
            flow_label: 0,
            payload_length: WireValue::Auto,
            next_header: WireValue::Auto,
            hop_limit: 64,
            source: Ipv6Addr::UNSPECIFIED,
            destination: Ipv6Addr::UNSPECIFIED,
        }
    }
}

fn ipv6_schema() -> &'static LayerSchema {
    static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
    static FIELDS: &[FieldSchema] = &[
        FieldSchema {
            name: "traffic_class",
            kind: FieldKind::Unsigned,
            derived: false,
            required: false,
            description: "IPv6 traffic class",
        },
        FieldSchema {
            name: "flow_label",
            kind: FieldKind::Unsigned,
            derived: false,
            required: false,
            description: "IPv6 flow label",
        },
        FieldSchema {
            name: "payload_length",
            kind: FieldKind::Unsigned,
            derived: true,
            required: false,
            description: "IPv6 payload length",
        },
        FieldSchema {
            name: "next_header",
            kind: FieldKind::Unsigned,
            derived: true,
            required: false,
            description: "Next-header discriminator",
        },
        FieldSchema {
            name: "hop_limit",
            kind: FieldKind::Unsigned,
            derived: false,
            required: true,
            description: "Hop limit",
        },
        FieldSchema {
            name: "source",
            kind: FieldKind::Ipv6,
            derived: false,
            required: true,
            description: "Source IPv6 address",
        },
        FieldSchema {
            name: "destination",
            kind: FieldKind::Ipv6,
            derived: false,
            required: true,
            description: "Destination IPv6 address",
        },
    ];
    SCHEMA.get_or_init(|| LayerSchema {
        protocol: protocol("ipv6"),
        name: "IPv6",
        fields: FIELDS,
    })
}

impl Layer for Ipv6 {
    impl_layer_boilerplate!(Ipv6, ipv6_schema);

    fn field(&self, name: &str) -> Option<FieldValue> {
        match name {
            "traffic_class" => Some(self.traffic_class.into()),
            "flow_label" => Some(self.flow_label.into()),
            "payload_length" => Some(wire_u16(&self.payload_length)),
            "next_header" => Some(wire_u8(&self.next_header)),
            "hop_limit" => Some(self.hop_limit.into()),
            "source" => Some(self.source.into()),
            "destination" => Some(self.destination.into()),
            _ => None,
        }
    }

    fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), FieldError> {
        match (name, value) {
            ("traffic_class", FieldValue::Unsigned(value)) => {
                self.traffic_class =
                    u8::try_from(value).map_err(|_| out_of_range(ipv6_schema(), name))?
            }
            ("flow_label", FieldValue::Unsigned(value)) => {
                self.flow_label = u32::try_from(value)
                    .ok()
                    .filter(|value| *value <= 0x000f_ffff)
                    .ok_or_else(|| out_of_range(ipv6_schema(), name))?
            }
            ("payload_length", value) => {
                return set_wire_u16(&mut self.payload_length, ipv6_schema(), name, value)
            }
            ("next_header", value) => {
                return set_wire_u8(&mut self.next_header, ipv6_schema(), name, value)
            }
            ("hop_limit", FieldValue::Unsigned(value)) => {
                self.hop_limit =
                    u8::try_from(value).map_err(|_| out_of_range(ipv6_schema(), name))?
            }
            ("source", value) => {
                self.source = ipv6(&value).ok_or_else(|| wrong_type(ipv6_schema(), name, "ipv6"))?
            }
            ("destination", value) => {
                self.destination =
                    ipv6(&value).ok_or_else(|| wrong_type(ipv6_schema(), name, "ipv6"))?
            }
            ("traffic_class" | "flow_label" | "hop_limit", _) => {
                return Err(wrong_type(ipv6_schema(), name, "unsigned"))
            }
            _ => return Err(unknown_field(ipv6_schema(), name)),
        }
        Ok(())
    }

    fn normalize(&mut self) {
        self.payload_length.normalize();
        self.next_header.normalize();
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Ipv6Codec;

impl LayerCodec for Ipv6Codec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("ipv6")
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["ip6"]
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Ipv6>()
            .ok_or_else(|| wrong_layer("ipv6", layer))?;
        if layer.flow_label > 0x000f_ffff {
            return Err(invalid("ipv6", "flow label exceeds 20 bits"));
        }
        let source = if layer.source.is_unspecified() {
            match context.build_context.source {
                Some(IpAddr::V6(source)) => source,
                _ => layer.source,
            }
        } else {
            layer.source
        };
        let srh_active = context
            .packet
            .iter()
            .skip(context.index + 1)
            // Only the contiguous IPv6 extension chain belongs to this
            // envelope. A routing header beyond a transport, opaque payload,
            // or nested network header belongs to another protocol scope.
            .take_while(|candidate| is_ipv6_extension_layer(*candidate))
            .find_map(|candidate| {
                let srh = candidate
                    .as_any()
                    .downcast_ref::<super::ipv6_ext::SegmentRoutingHeader>()?;
                let last = srh.segments.len().checked_sub(1)?;
                let segments_left = match srh.segments_left {
                    WireValue::Auto => last,
                    WireValue::Exact(value) => usize::from(value).min(last),
                    WireValue::Raw(_) => return None,
                };
                srh.segments.get(last - segments_left).copied()
            });
        let mut diagnostics = Vec::new();
        if let Some(active) = srh_active {
            if !layer.destination.is_unspecified() && layer.destination != active {
                strict_or_diagnostic(
                    "ipv6",
                    "build.srh_outer_destination",
                    "destination",
                    format!(
                        "outer destination {} does not match active SRH segment {active}",
                        layer.destination
                    ),
                    context,
                    &mut diagnostics,
                )?;
            }
        }
        let destination = if layer.destination.is_unspecified() {
            srh_active.unwrap_or(match context.build_context.destination {
                Some(IpAddr::V6(destination)) => destination,
                _ => layer.destination,
            })
        } else {
            layer.destination
        };
        let covered_payload = payload_without_padding("ipv6", payload, context)?;
        let expected_length = u16::try_from(covered_payload.len())
            .map_err(|_| invalid("ipv6", "jumbograms are not supported"))?;
        let (payload_length, materialized_length) = resolve_u16(
            "ipv6",
            "payload_length",
            &layer.payload_length,
            expected_length,
            true,
            context.mode,
            &mut diagnostics,
        )?;
        let (expected_next, validate_next) = expected_next("ipv6", context, 59);
        validate_auto_raw_discriminator(
            "ipv6",
            "next_header",
            matches!(layer.next_header, WireValue::Auto),
            context,
            &mut diagnostics,
        )?;
        let (next_header, materialized_next) = resolve_u8(
            "ipv6",
            "next_header",
            &layer.next_header,
            expected_next,
            validate_next,
            context.mode,
            &mut diagnostics,
        )?;
        validate_raw_child_discriminator(
            "ipv6",
            u64::from(next_header),
            context,
            &mut diagnostics,
        )?;
        validate_ipv6_routing_child("ipv6", next_header, context, &mut diagnostics)?;
        let version_flow = (6u32 << 28) | (u32::from(layer.traffic_class) << 20) | layer.flow_label;
        let mut prefix = Vec::with_capacity(IPV6_LEN);
        prefix.extend_from_slice(&version_flow.to_be_bytes());
        prefix.extend_from_slice(&payload_length.to_be_bytes());
        prefix.push(next_header);
        prefix.push(layer.hop_limit);
        prefix.extend_from_slice(&source.octets());
        prefix.extend_from_slice(&destination.octets());
        let mut materialized = layer.clone();
        materialized.payload_length = materialized_length;
        materialized.next_header = materialized_next;
        materialized.source = source;
        materialized.destination = destination;
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: vec![
                field_layout("traffic_class", 0, 4),
                field_layout("flow_label", 0, 4),
                field_layout("payload_length", 4, 6),
                field_layout("next_header", 6, 7),
                field_layout("hop_limit", 7, 8),
                field_layout("source", 8, 24),
                field_layout("destination", 24, 40),
            ],
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < IPV6_LEN {
            return Err(truncated("ipv6", IPV6_LEN, input.len()));
        }
        if input[0] >> 4 != 6 {
            return Err(invalid(
                "ipv6",
                format!("version is {}, not 6", input[0] >> 4),
            ));
        }
        let payload_length = usize::from(u16::from_be_bytes([input[4], input[5]]));
        // A jumbogram must start with a Hop-by-Hop header carrying the Jumbo
        // Payload option. With any other next header, the declared IPv6
        // payload is empty and any remaining capture bytes are outside it;
        // the dissector will classify them as link padding or a malformed
        // trailer according to the enclosing link context.
        if payload_length == 0 && input.len() > IPV6_LEN && input[6] == 0 {
            return Err(CodecError::Unsupported {
                protocol: protocol("ipv6"),
                message: "IPv6 jumbogram payload requires a Hop-by-Hop Jumbo Payload option"
                    .to_string(),
            });
        }
        let required = IPV6_LEN
            .checked_add(payload_length)
            .ok_or_else(|| invalid("ipv6", "payload length overflow"))?;
        if input.len() < required {
            return Err(truncated("ipv6", required, input.len()));
        }
        let first = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
        let mut source_bytes = [0; 16];
        source_bytes.copy_from_slice(&input[8..24]);
        let source = Ipv6Addr::from(source_bytes);
        let mut destination_bytes = [0; 16];
        destination_bytes.copy_from_slice(&input[24..40]);
        let destination = Ipv6Addr::from(destination_bytes);
        let next = input[6];
        Ok(DecodedLayerValue {
            layer: Box::new(Ipv6 {
                traffic_class: ((first >> 20) & 0xff) as u8,
                flow_label: first & 0x000f_ffff,
                payload_length: WireValue::Exact(payload_length as u16),
                next_header: WireValue::Exact(next),
                hop_limit: input[7],
                source,
                destination,
            }),
            consumed: IPV6_LEN,
            payload_offset: IPV6_LEN,
            payload_len: payload_length,
            next: vec![Discriminator(u64::from(next))],
            fields: vec![
                field_layout("traffic_class", 0, 4),
                field_layout("flow_label", 0, 4),
                field_layout("payload_length", 4, 6),
                field_layout("next_header", 6, 7),
                field_layout("hop_limit", 7, 8),
                field_layout("source", 8, 24),
                field_layout("destination", 24, 40),
            ],
            diagnostics: Vec::new(),
            stop: payload_length == 0,
            network: Some(network_from_addresses(source.into(), destination.into())),
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(
            Ipv6::default(),
            &aliased_fields("ipv6", fields, &[("src", "source"), ("dst", "destination")])?,
        )
    }
}

fn expected_next(parent: &str, context: &LayerEncodeContext<'_>, fallback: u8) -> (u8, bool) {
    let Some(child) = context.child else {
        return (fallback, false);
    };
    if child.protocol_id().as_str() == "raw" {
        let expected = context
            .registry
            .discriminator_for(&protocol(parent), &child.protocol_id())
            .and_then(|value| u8::try_from(value.0).ok())
            .unwrap_or(fallback);
        return (expected, false);
    }
    context
        .registry
        .discriminator_for(&protocol(parent), &binding_protocol(child))
        .and_then(|value| u8::try_from(value.0).ok())
        .map_or((fallback, false), |value| (value, true))
}

pub(crate) fn encode_network(
    context: &LayerEncodeContext<'_>,
) -> Result<NetworkEnvelope, CodecError> {
    for index in (0..context.index).rev() {
        let Some(layer) = context.packet.layer(index) else {
            continue;
        };
        if let Some(ipv4) = layer.as_any().downcast_ref::<Ipv4>() {
            let source = if ipv4.source.is_unspecified() {
                context
                    .build_context
                    .source
                    .and_then(|source| match source {
                        IpAddr::V4(source) => Some(source),
                        IpAddr::V6(_) => None,
                    })
                    .unwrap_or(ipv4.source)
            } else {
                ipv4.source
            };
            let destination = if ipv4.destination.is_unspecified() {
                context
                    .build_context
                    .destination
                    .and_then(|destination| match destination {
                        IpAddr::V4(destination) => Some(destination),
                        IpAddr::V6(_) => None,
                    })
                    .unwrap_or(ipv4.destination)
            } else {
                ipv4.destination
            };
            return Ok(network_from_addresses(source.into(), destination.into()));
        }
        if let Some(ipv6) = layer.as_any().downcast_ref::<Ipv6>() {
            // Only routing headers inside the nearest IPv6 envelope can
            // replace its pseudo-header destination. An SRH belonging to an
            // outer tunnel must not affect an encapsulated transport.
            let segment_routing_destination = ((index + 1)..context.index)
                .filter_map(|candidate_index| context.packet.layer(candidate_index))
                .take_while(|candidate| is_ipv6_extension_layer(*candidate))
                .filter_map(|candidate| {
                    candidate
                        .as_any()
                        .downcast_ref::<super::ipv6_ext::SegmentRoutingHeader>()?
                        .segments
                        .last()
                        .copied()
                })
                .last();
            let source = if ipv6.source.is_unspecified() {
                context
                    .build_context
                    .source
                    .and_then(|source| match source {
                        IpAddr::V6(source) => Some(source),
                        IpAddr::V4(_) => None,
                    })
                    .unwrap_or(ipv6.source)
            } else {
                ipv6.source
            };
            let destination = if ipv6.destination.is_unspecified() {
                context
                    .build_context
                    .destination
                    .and_then(|destination| match destination {
                        IpAddr::V6(destination) => Some(destination),
                        IpAddr::V4(_) => None,
                    })
                    .unwrap_or(ipv6.destination)
            } else {
                ipv6.destination
            };
            return Ok(network_from_addresses(
                source.into(),
                segment_routing_destination.unwrap_or(destination).into(),
            ));
        }
    }
    match (
        context.build_context.source,
        context.build_context.destination,
    ) {
        (Some(source), Some(destination)) if source.is_ipv4() == destination.is_ipv4() => {
            Ok(NetworkEnvelope {
                source,
                destination,
            })
        }
        _ => Err(invalid(
            "transport",
            "transport checksum requires matching source and destination IP addresses",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::packet::internal::{BuildContext, BuildOptions, Builder, Packet, ProtocolRegistry};
    use crate::protocol::builtin_impl::{BuiltinProtocols, SegmentRoutingHeader, Udp};

    fn address(value: &str) -> Ipv6Addr {
        value.parse().unwrap()
    }

    fn tunnel_registry() -> Arc<ProtocolRegistry> {
        let mut builder = ProtocolRegistry::builder();
        builder.module(&BuiltinProtocols).unwrap();
        builder.bind("ipv6", 41, "ipv6", 100).unwrap();
        builder.bind("ipv6_srh", 41, "ipv6", 100).unwrap();
        Arc::new(builder.build().unwrap())
    }

    #[test]
    fn outer_srh_does_not_change_inner_ipv6_udp_checksum() {
        let inner_source = address("2001:db8:1::1");
        let inner_destination = address("2001:db8:1::2");
        let mut packet = Packet::new();
        packet
            .push(Ipv6 {
                next_header: WireValue::Exact(43),
                source: address("2001:db8::1"),
                destination: address("2001:db8::10"),
                ..Ipv6::default()
            })
            .push(SegmentRoutingHeader {
                next_header: WireValue::Exact(41),
                segments: vec![address("2001:db8::10")],
                ..SegmentRoutingHeader::default()
            })
            .push(Ipv6 {
                source: inner_source,
                destination: inner_destination,
                ..Ipv6::default()
            })
            .push(Udp::default());

        let built = Builder::new(tunnel_registry())
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap();
        let udp_offset = 40 + 24 + 40;
        assert_eq!(
            super::super::common::transport_checksum(
                network_from_addresses(inner_source.into(), inner_destination.into()),
                17,
                &built.bytes[udp_offset..],
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn inner_srh_does_not_override_outer_ipv6_destination() {
        let mut packet = Packet::new();
        packet
            .push(Ipv6 {
                next_header: WireValue::Exact(41),
                source: address("2001:db8::1"),
                destination: address("2001:db8::2"),
                ..Ipv6::default()
            })
            .push(Ipv6 {
                source: address("2001:db8:1::1"),
                destination: address("2001:db8:1::10"),
                ..Ipv6::default()
            })
            .push(SegmentRoutingHeader {
                segments: vec![address("2001:db8:1::10")],
                ..SegmentRoutingHeader::default()
            })
            .push(Udp::default());

        Builder::new(tunnel_registry())
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap();
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct RawIpCodec;

impl LayerCodec for RawIpCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("raw_ip")
    }
    fn accepts_decoded_protocol(&self, protocol: &ProtocolId) -> bool {
        matches!(protocol.as_str(), "ipv4" | "ipv6")
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["rawip"]
    }

    fn encode(
        &self,
        _layer: &dyn Layer,
        _payload: &[u8],
        _context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        Err(CodecError::Unsupported {
            protocol: protocol("raw_ip"),
            message: "raw_ip is a decode-only link root; build IPv4 or IPv6 directly".to_string(),
        })
    }

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        let Some(version) = input.first().map(|byte| byte >> 4) else {
            return Err(truncated("raw_ip", 1, 0));
        };
        match version {
            4 => Ipv4Codec.decode(input, context),
            6 => Ipv6Codec.decode(input, context),
            _ => Err(invalid(
                "raw_ip",
                format!("unknown IP version nibble {version}"),
            )),
        }
    }

    fn make_layer(
        &self,
        _fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        Err(CodecError::Unsupported {
            protocol: protocol("raw_ip"),
            message: "raw_ip has no constructible layer".to_string(),
        })
    }
}
