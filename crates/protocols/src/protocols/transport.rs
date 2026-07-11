// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::OnceLock;

use bytes::Bytes;

use crate::core::{
    CodecError, DecodedLayerValue, Diagnostic, Discriminator, EncodedLayer, FieldError, FieldKind,
    FieldSchema, FieldValue, Layer, LayerCodec, LayerDecodeContext, LayerEncodeContext,
    LayerSchema, ProtocolId, WireValue,
};

use super::common::{
    aliased_fields, bytes, field_layout, impl_layer_boilerplate, invalid, make_layer, out_of_range,
    payload_without_padding, protocol, resolve_u16, set_wire_u16, transport_checksum, truncated,
    unknown_field, wire_u16, wrong_layer, wrong_type,
};
use super::ip::encode_network;

const UDP_LEN: usize = 8;
const TCP_MIN_LEN: usize = 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Udp {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: WireValue<u16>,
    pub checksum: WireValue<u16>,
}

impl Default for Udp {
    fn default() -> Self {
        Self {
            source_port: 53_000,
            destination_port: 53,
            length: WireValue::Auto,
            checksum: WireValue::Auto,
        }
    }
}

fn udp_schema() -> &'static LayerSchema {
    static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
    static FIELDS: &[FieldSchema] = &[
        FieldSchema {
            name: "source_port",
            kind: FieldKind::Unsigned,
            derived: false,
            required: true,
            description: "UDP source port",
        },
        FieldSchema {
            name: "destination_port",
            kind: FieldKind::Unsigned,
            derived: false,
            required: true,
            description: "UDP destination port",
        },
        FieldSchema {
            name: "length",
            kind: FieldKind::Unsigned,
            derived: true,
            required: false,
            description: "UDP datagram length",
        },
        FieldSchema {
            name: "checksum",
            kind: FieldKind::Unsigned,
            derived: true,
            required: false,
            description: "UDP checksum",
        },
    ];
    SCHEMA.get_or_init(|| LayerSchema {
        protocol: protocol("udp"),
        name: "UDP",
        fields: FIELDS,
    })
}

impl Layer for Udp {
    impl_layer_boilerplate!(Udp, udp_schema);

    fn field(&self, name: &str) -> Option<FieldValue> {
        match name {
            "source_port" => Some(self.source_port.into()),
            "destination_port" => Some(self.destination_port.into()),
            "length" => Some(wire_u16(&self.length)),
            "checksum" => Some(wire_u16(&self.checksum)),
            _ => None,
        }
    }

    fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), FieldError> {
        match (name, value) {
            ("source_port", FieldValue::Unsigned(value)) => {
                self.source_port =
                    u16::try_from(value).map_err(|_| out_of_range(udp_schema(), name))?
            }
            ("destination_port", FieldValue::Unsigned(value)) => {
                self.destination_port =
                    u16::try_from(value).map_err(|_| out_of_range(udp_schema(), name))?
            }
            ("length", value) => return set_wire_u16(&mut self.length, udp_schema(), name, value),
            ("checksum", value) => {
                return set_wire_u16(&mut self.checksum, udp_schema(), name, value)
            }
            ("source_port" | "destination_port", _) => {
                return Err(wrong_type(udp_schema(), name, "unsigned"))
            }
            _ => return Err(unknown_field(udp_schema(), name)),
        }
        Ok(())
    }

    fn normalize(&mut self) {
        self.length.normalize();
        self.checksum.normalize();
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UdpCodec;

impl LayerCodec for UdpCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("udp")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Udp>()
            .ok_or_else(|| wrong_layer("udp", layer))?;
        let covered_payload = payload_without_padding("udp", payload, context)?;
        let expected_length = UDP_LEN
            .checked_add(covered_payload.len())
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| invalid("udp", "datagram exceeds UDP length range"))?;
        let mut diagnostics = Vec::new();
        let (length, materialized_length) = resolve_u16(
            "udp",
            "length",
            &layer.length,
            expected_length,
            true,
            context.mode,
            &mut diagnostics,
        )?;
        let network = encode_network(context)?;
        let mut segment = Vec::with_capacity(usize::from(expected_length));
        segment.extend_from_slice(&layer.source_port.to_be_bytes());
        segment.extend_from_slice(&layer.destination_port.to_be_bytes());
        segment.extend_from_slice(&length.to_be_bytes());
        segment.extend_from_slice(&[0, 0]);
        segment.extend_from_slice(covered_payload);
        let mut checksum_expected = transport_checksum(network, 17, &segment)?;
        if checksum_expected == 0 {
            checksum_expected = 0xffff;
        }
        let ipv4_omitted = matches!(network.source, IpAddr::V4(_))
            && matches!(layer.checksum, WireValue::Exact(0));
        let (checksum, materialized_checksum) = resolve_u16(
            "udp",
            "checksum",
            &layer.checksum,
            checksum_expected,
            !ipv4_omitted,
            context.mode,
            &mut diagnostics,
        )?;
        let mut prefix = segment[..UDP_LEN].to_vec();
        prefix[6..8].copy_from_slice(&checksum.to_be_bytes());
        let mut materialized = layer.clone();
        materialized.length = materialized_length;
        materialized.checksum = materialized_checksum;
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: vec![
                field_layout("source_port", 0, 2),
                field_layout("destination_port", 2, 4),
                field_layout("length", 4, 6),
                field_layout("checksum", 6, 8),
            ],
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < UDP_LEN {
            return Err(truncated("udp", UDP_LEN, input.len()));
        }
        let length = usize::from(u16::from_be_bytes([input[4], input[5]]));
        if length < UDP_LEN {
            return Err(invalid(
                "udp",
                format!("length {length} is below {UDP_LEN}"),
            ));
        }
        if input.len() < length {
            return Err(truncated("udp", length, input.len()));
        }
        let checksum_value = u16::from_be_bytes([input[6], input[7]]);
        let mut diagnostics = Vec::new();
        if context.verify_checksums {
            if let Some(network) = context.network {
                if checksum_value == 0 {
                    if matches!(network.source, IpAddr::V6(_)) {
                        diagnostics.push(
                            Diagnostic::warning(
                                "decode.udp_checksum",
                                "zero UDP checksum is invalid for IPv6",
                            )
                            .at_field("checksum"),
                        );
                    }
                } else if transport_checksum(network, 17, &input[..length])? != 0 {
                    diagnostics.push(
                        Diagnostic::warning("decode.udp_checksum", "UDP checksum mismatch")
                            .at_field("checksum"),
                    );
                }
            }
        }
        let payload_len = length - UDP_LEN;
        Ok(DecodedLayerValue {
            layer: Box::new(Udp {
                source_port: u16::from_be_bytes([input[0], input[1]]),
                destination_port: u16::from_be_bytes([input[2], input[3]]),
                length: WireValue::Exact(length as u16),
                checksum: WireValue::Exact(checksum_value),
            }),
            consumed: UDP_LEN,
            payload_offset: UDP_LEN,
            payload_len,
            next: if payload_len == 0 {
                Vec::new()
            } else {
                vec![Discriminator(0)]
            },
            fields: vec![
                field_layout("source_port", 0, 2),
                field_layout("destination_port", 2, 4),
                field_layout("length", 4, 6),
                field_layout("checksum", 6, 8),
            ],
            diagnostics,
            stop: payload_len == 0,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(
            Udp::default(),
            &aliased_fields(
                "udp",
                fields,
                &[("sport", "source_port"), ("dport", "destination_port")],
            )?,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tcp {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub reserved_bits: u8,
    pub flags: u16,
    pub window: u16,
    pub checksum: WireValue<u16>,
    pub urgent_pointer: u16,
    pub options: Bytes,
}

impl Tcp {
    pub const FIN: u16 = 0x001;
    pub const SYN: u16 = 0x002;
    pub const RST: u16 = 0x004;
    pub const PSH: u16 = 0x008;
    pub const ACK: u16 = 0x010;
    pub const URG: u16 = 0x020;
    pub const ECE: u16 = 0x040;
    pub const CWR: u16 = 0x080;
    pub const NS: u16 = 0x100;
}

impl Default for Tcp {
    fn default() -> Self {
        Self {
            source_port: 50_000,
            destination_port: 80,
            sequence: 0,
            acknowledgment: 0,
            reserved_bits: 0,
            flags: Self::SYN,
            window: 65_535,
            checksum: WireValue::Auto,
            urgent_pointer: 0,
            options: Bytes::new(),
        }
    }
}

fn tcp_schema() -> &'static LayerSchema {
    static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
    static FIELDS: &[FieldSchema] = &[
        FieldSchema {
            name: "source_port",
            kind: FieldKind::Unsigned,
            derived: false,
            required: true,
            description: "TCP source port",
        },
        FieldSchema {
            name: "destination_port",
            kind: FieldKind::Unsigned,
            derived: false,
            required: true,
            description: "TCP destination port",
        },
        FieldSchema {
            name: "sequence",
            kind: FieldKind::Unsigned,
            derived: false,
            required: true,
            description: "Sequence number",
        },
        FieldSchema {
            name: "acknowledgment",
            kind: FieldKind::Unsigned,
            derived: false,
            required: false,
            description: "Acknowledgment number",
        },
        FieldSchema {
            name: "reserved_bits",
            kind: FieldKind::Unsigned,
            derived: false,
            required: false,
            description: "Three reserved TCP header bits",
        },
        FieldSchema {
            name: "flags",
            kind: FieldKind::Unsigned,
            derived: false,
            required: true,
            description: "Nine TCP control flags",
        },
        FieldSchema {
            name: "window",
            kind: FieldKind::Unsigned,
            derived: false,
            required: true,
            description: "Receive window",
        },
        FieldSchema {
            name: "checksum",
            kind: FieldKind::Unsigned,
            derived: true,
            required: false,
            description: "TCP checksum",
        },
        FieldSchema {
            name: "urgent_pointer",
            kind: FieldKind::Unsigned,
            derived: false,
            required: false,
            description: "Urgent pointer",
        },
        FieldSchema {
            name: "options",
            kind: FieldKind::Bytes,
            derived: false,
            required: false,
            description: "Verbatim standard or unknown TCP options",
        },
    ];
    SCHEMA.get_or_init(|| LayerSchema {
        protocol: protocol("tcp"),
        name: "TCP",
        fields: FIELDS,
    })
}

impl Layer for Tcp {
    impl_layer_boilerplate!(Tcp, tcp_schema);

    fn field(&self, name: &str) -> Option<FieldValue> {
        match name {
            "source_port" => Some(self.source_port.into()),
            "destination_port" => Some(self.destination_port.into()),
            "sequence" => Some(self.sequence.into()),
            "acknowledgment" => Some(self.acknowledgment.into()),
            "reserved_bits" => Some(self.reserved_bits.into()),
            "flags" => Some(self.flags.into()),
            "window" => Some(self.window.into()),
            "checksum" => Some(wire_u16(&self.checksum)),
            "urgent_pointer" => Some(self.urgent_pointer.into()),
            "options" => Some(self.options.clone().into()),
            _ => None,
        }
    }

    fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), FieldError> {
        match (name, value) {
            ("source_port", FieldValue::Unsigned(value)) => {
                self.source_port =
                    u16::try_from(value).map_err(|_| out_of_range(tcp_schema(), name))?
            }
            ("destination_port", FieldValue::Unsigned(value)) => {
                self.destination_port =
                    u16::try_from(value).map_err(|_| out_of_range(tcp_schema(), name))?
            }
            ("sequence", FieldValue::Unsigned(value)) => {
                self.sequence =
                    u32::try_from(value).map_err(|_| out_of_range(tcp_schema(), name))?
            }
            ("acknowledgment", FieldValue::Unsigned(value)) => {
                self.acknowledgment =
                    u32::try_from(value).map_err(|_| out_of_range(tcp_schema(), name))?
            }
            ("reserved_bits", FieldValue::Unsigned(value)) => {
                self.reserved_bits = u8::try_from(value)
                    .ok()
                    .filter(|value| *value <= 7)
                    .ok_or_else(|| out_of_range(tcp_schema(), name))?
            }
            ("flags", FieldValue::Unsigned(value)) => {
                self.flags = u16::try_from(value)
                    .ok()
                    .filter(|value| *value <= 0x01ff)
                    .ok_or_else(|| out_of_range(tcp_schema(), name))?
            }
            ("window", FieldValue::Unsigned(value)) => {
                self.window = u16::try_from(value).map_err(|_| out_of_range(tcp_schema(), name))?
            }
            ("checksum", value) => {
                return set_wire_u16(&mut self.checksum, tcp_schema(), name, value)
            }
            ("urgent_pointer", FieldValue::Unsigned(value)) => {
                self.urgent_pointer =
                    u16::try_from(value).map_err(|_| out_of_range(tcp_schema(), name))?
            }
            ("options", value) => {
                self.options =
                    bytes(&value).ok_or_else(|| wrong_type(tcp_schema(), name, "bytes"))?
            }
            (
                "source_port" | "destination_port" | "sequence" | "acknowledgment"
                | "reserved_bits" | "flags" | "window" | "urgent_pointer",
                _,
            ) => return Err(wrong_type(tcp_schema(), name, "unsigned")),
            _ => return Err(unknown_field(tcp_schema(), name)),
        }
        Ok(())
    }

    fn normalize(&mut self) {
        self.checksum.normalize();
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TcpCodec;

impl LayerCodec for TcpCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("tcp")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Tcp>()
            .ok_or_else(|| wrong_layer("tcp", layer))?;
        if layer.flags > 0x01ff {
            return Err(invalid("tcp", "flags exceed nine bits"));
        }
        if layer.reserved_bits > 7 {
            return Err(invalid("tcp", "reserved bits exceed three bits"));
        }
        if layer.options.len() > 40 {
            return Err(invalid("tcp", "options exceed the 40-byte TCP limit"));
        }
        let mut diagnostics = Vec::new();
        if layer.reserved_bits != 0 {
            let message = "reserved TCP header bits are non-zero";
            if context.mode == crate::core::BuildMode::Strict {
                return Err(invalid("tcp", message));
            }
            diagnostics.push(
                Diagnostic::warning("build.tcp_reserved_bits", message).at_field("reserved_bits"),
            );
        }
        let mut options = layer.options.to_vec();
        let padding = (4 - (options.len() % 4)) % 4;
        if padding != 0 {
            options.resize(options.len() + padding, 0);
            diagnostics.push(
                Diagnostic::warning(
                    "build.tcp_options_padded",
                    format!("padded TCP options with {padding} zero byte(s)"),
                )
                .at_field("options"),
            );
        }
        let header_len = TCP_MIN_LEN + options.len();
        let data_offset =
            u8::try_from(header_len / 4).map_err(|_| invalid("tcp", "header length overflow"))?;
        let mut segment = vec![0u8; header_len];
        segment[0..2].copy_from_slice(&layer.source_port.to_be_bytes());
        segment[2..4].copy_from_slice(&layer.destination_port.to_be_bytes());
        segment[4..8].copy_from_slice(&layer.sequence.to_be_bytes());
        segment[8..12].copy_from_slice(&layer.acknowledgment.to_be_bytes());
        segment[12] =
            (data_offset << 4) | ((layer.reserved_bits & 7) << 1) | ((layer.flags >> 8) as u8 & 1);
        segment[13] = layer.flags as u8;
        segment[14..16].copy_from_slice(&layer.window.to_be_bytes());
        segment[18..20].copy_from_slice(&layer.urgent_pointer.to_be_bytes());
        segment[20..].copy_from_slice(&options);
        segment.extend_from_slice(payload_without_padding("tcp", payload, context)?);
        let network = encode_network(context)?;
        let checksum_expected = transport_checksum(network, 6, &segment)?;
        let (checksum, materialized_checksum) = resolve_u16(
            "tcp",
            "checksum",
            &layer.checksum,
            checksum_expected,
            true,
            context.mode,
            &mut diagnostics,
        )?;
        let mut prefix = segment[..header_len].to_vec();
        prefix[16..18].copy_from_slice(&checksum.to_be_bytes());
        let mut materialized = layer.clone();
        materialized.checksum = materialized_checksum;
        materialized.options = Bytes::from(options);
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: tcp_layout(header_len),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < TCP_MIN_LEN {
            return Err(truncated("tcp", TCP_MIN_LEN, input.len()));
        }
        let data_offset = usize::from(input[12] >> 4);
        if data_offset < 5 {
            return Err(invalid(
                "tcp",
                format!("data offset {data_offset} is below 5"),
            ));
        }
        let header_len = data_offset
            .checked_mul(4)
            .ok_or_else(|| invalid("tcp", "data offset overflow"))?;
        if input.len() < header_len {
            return Err(truncated("tcp", header_len, input.len()));
        }
        let checksum_value = u16::from_be_bytes([input[16], input[17]]);
        let mut diagnostics = Vec::new();
        let reserved_bits = (input[12] >> 1) & 7;
        if reserved_bits != 0 {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.tcp_reserved_bits",
                    "reserved TCP header bits are non-zero",
                )
                .at_field("reserved_bits"),
            );
        }
        if context.verify_checksums {
            if let Some(network) = context.network {
                if transport_checksum(network, 6, input)? != 0 {
                    diagnostics.push(
                        Diagnostic::warning("decode.tcp_checksum", "TCP checksum mismatch")
                            .at_field("checksum"),
                    );
                }
            }
        }
        let payload_len = input.len() - header_len;
        Ok(DecodedLayerValue {
            layer: Box::new(Tcp {
                source_port: u16::from_be_bytes([input[0], input[1]]),
                destination_port: u16::from_be_bytes([input[2], input[3]]),
                sequence: u32::from_be_bytes([input[4], input[5], input[6], input[7]]),
                acknowledgment: u32::from_be_bytes([input[8], input[9], input[10], input[11]]),
                reserved_bits,
                flags: (u16::from(input[12] & 1) << 8) | u16::from(input[13]),
                window: u16::from_be_bytes([input[14], input[15]]),
                checksum: WireValue::Exact(checksum_value),
                urgent_pointer: u16::from_be_bytes([input[18], input[19]]),
                options: Bytes::copy_from_slice(&input[20..header_len]),
            }),
            consumed: header_len,
            payload_offset: header_len,
            payload_len,
            next: if payload_len == 0 {
                Vec::new()
            } else {
                vec![Discriminator(0)]
            },
            fields: tcp_layout(header_len),
            diagnostics,
            stop: payload_len == 0,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(
            Tcp::default(),
            &aliased_fields(
                "tcp",
                fields,
                &[("sport", "source_port"), ("dport", "destination_port")],
            )?,
        )
    }
}

fn tcp_layout(header_len: usize) -> Vec<crate::core::FieldLayout> {
    vec![
        field_layout("source_port", 0, 2),
        field_layout("destination_port", 2, 4),
        field_layout("sequence", 4, 8),
        field_layout("acknowledgment", 8, 12),
        field_layout("reserved_bits", 12, 13),
        field_layout("flags", 12, 14),
        field_layout("window", 14, 16),
        field_layout("checksum", 16, 18),
        field_layout("urgent_pointer", 18, 20),
        field_layout("options", 20, header_len),
    ]
}
