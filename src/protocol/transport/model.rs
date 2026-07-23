// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::IpAddr;

use bytes::Bytes;

use crate::packet::{
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    diagnostic::Diagnostic,
    field::{FieldValue, WireValue},
    layer::{Layer, ProtocolId, reflect_get, reflect_set, reflective_layer},
    registry::Discriminator,
};

use super::super::common::{
    ValueExpectation, aliased_fields, invalid, make_layer, out_of_range, payload_without_padding,
    protocol, resolve_u16, transport_checksum, transport_checksum_parts, truncated, wrong_layer,
    wrong_type,
};
use super::super::network::encode_network;

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

reflective_layer! {
    fn udp_schema() => { protocol: protocol("udp"), name: "UDP" }
    impl Udp {
        "source_port" => {
            kind: Unsigned, derived: false, required: true,
            description: "UDP source port",
            get |layer| Some(layer.source_port.into()),
            set |layer, value, name| match value {
                FieldValue::Unsigned(value) => {
                    layer.source_port = u16::try_from(value)
                        .map_err(|_| out_of_range(udp_schema(), name))?;
                    Ok(())
                }
                _ => Err(wrong_type(udp_schema(), name, "unsigned")),
            },
            layout: (0, 2)
        },
        "destination_port" => {
            kind: Unsigned, derived: false, required: true,
            description: "UDP destination port",
            get |layer| Some(layer.destination_port.into()),
            set |layer, value, name| match value {
                FieldValue::Unsigned(value) => {
                    layer.destination_port = u16::try_from(value)
                        .map_err(|_| out_of_range(udp_schema(), name))?;
                    Ok(())
                }
                _ => Err(wrong_type(udp_schema(), name, "unsigned")),
            },
            layout: (2, 4)
        },
        "length" => {
            kind: Unsigned, derived: true, required: false,
            description: "UDP datagram length",
            get |layer| Some(reflect_get(&layer.length)),
            set |layer, value, name| reflect_set(&mut layer.length, udp_schema(), name, value),
            layout: (4, 6)
        },
        "checksum" => {
            kind: Unsigned, derived: true, required: false,
            description: "UDP checksum",
            get |layer| Some(reflect_get(&layer.checksum)),
            set |layer, value, name| reflect_set(&mut layer.checksum, udp_schema(), name, value),
            layout: (6, 8)
        },
        normalize |layer| {
            layer.length.normalize();
            layer.checksum.normalize();
        }
    }
    layout fn udp_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct UdpCodec;

impl LayerCodec for UdpCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("udp")
    }

    fn aliases(&self) -> &'static [&'static str] {
        super::super::support::aliases(self.protocol_id().as_str())
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
            ValueExpectation::Required(expected_length),
            context.mode,
            &mut diagnostics,
        )?;
        let network = encode_network(context)?;
        let mut header = [0_u8; UDP_LEN];
        header[0..2].copy_from_slice(&layer.source_port.to_be_bytes());
        header[2..4].copy_from_slice(&layer.destination_port.to_be_bytes());
        header[4..6].copy_from_slice(&length.to_be_bytes());
        let mut checksum_expected =
            transport_checksum_parts(network, 17, &[&header, covered_payload])?;
        if checksum_expected == 0 {
            checksum_expected = 0xffff;
        }
        let ipv4_omitted = matches!(network.source, IpAddr::V4(_))
            && matches!(layer.checksum, WireValue::Exact(0));
        let (checksum, materialized_checksum) = resolve_u16(
            "udp",
            "checksum",
            &layer.checksum,
            if ipv4_omitted {
                ValueExpectation::Suggested(checksum_expected)
            } else {
                ValueExpectation::Required(checksum_expected)
            },
            context.mode,
            &mut diagnostics,
        )?;
        header[6..8].copy_from_slice(&checksum.to_be_bytes());
        let mut materialized = layer.clone();
        materialized.length = materialized_length;
        materialized.checksum = materialized_checksum;
        Ok(EncodedLayer {
            prefix: header.to_vec(),
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: udp_layout(),
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
        if context.verify_checksums
            && let Some(network) = context.network
        {
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
            fields: udp_layout(),
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

reflective_layer! {
    fn tcp_schema() => { protocol: protocol("tcp"), name: "TCP" }
    impl Tcp {
        "source_port" => { kind: Unsigned, derived: false, required: true, description: "TCP source port",
            get |layer| Some(reflect_get(&layer.source_port)), set |layer, value, name| reflect_set(&mut layer.source_port, tcp_schema(), name, value), layout: (0, 2) },
        "destination_port" => { kind: Unsigned, derived: false, required: true, description: "TCP destination port",
            get |layer| Some(reflect_get(&layer.destination_port)), set |layer, value, name| reflect_set(&mut layer.destination_port, tcp_schema(), name, value), layout: (2, 4) },
        "sequence" => { kind: Unsigned, derived: false, required: true, description: "Sequence number",
            get |layer| Some(reflect_get(&layer.sequence)), set |layer, value, name| reflect_set(&mut layer.sequence, tcp_schema(), name, value), layout: (4, 8) },
        "acknowledgment" => { kind: Unsigned, derived: false, required: false, description: "Acknowledgment number",
            get |layer| Some(reflect_get(&layer.acknowledgment)), set |layer, value, name| reflect_set(&mut layer.acknowledgment, tcp_schema(), name, value), layout: (8, 12) },
        "reserved_bits" => { kind: Unsigned, derived: false, required: false, description: "Three reserved TCP header bits",
            get |layer| Some(reflect_get(&layer.reserved_bits)), set |layer, value, name| match value {
                FieldValue::Unsigned(value) => { layer.reserved_bits = u8::try_from(value).ok().filter(|value| *value <= 7).ok_or_else(|| out_of_range(tcp_schema(), name))?; Ok(()) },
                _ => Err(wrong_type(tcp_schema(), name, "unsigned")),
            }, layout: (12, 13) },
        "flags" => { kind: Unsigned, derived: false, required: true, description: "Nine TCP control flags",
            get |layer| Some(reflect_get(&layer.flags)), set |layer, value, name| match value {
                FieldValue::Unsigned(value) => { layer.flags = u16::try_from(value).ok().filter(|value| *value <= 0x01ff).ok_or_else(|| out_of_range(tcp_schema(), name))?; Ok(()) },
                _ => Err(wrong_type(tcp_schema(), name, "unsigned")),
            }, layout: (12, 14) },
        "window" => { kind: Unsigned, derived: false, required: true, description: "Receive window",
            get |layer| Some(reflect_get(&layer.window)), set |layer, value, name| reflect_set(&mut layer.window, tcp_schema(), name, value), layout: (14, 16) },
        "checksum" => { kind: Unsigned, derived: true, required: false, description: "TCP checksum",
            get |layer| Some(reflect_get(&layer.checksum)), set |layer, value, name| reflect_set(&mut layer.checksum, tcp_schema(), name, value), layout: (16, 18) },
        "urgent_pointer" => { kind: Unsigned, derived: false, required: false, description: "Urgent pointer",
            get |layer| Some(reflect_get(&layer.urgent_pointer)), set |layer, value, name| reflect_set(&mut layer.urgent_pointer, tcp_schema(), name, value), layout: (18, 20) },
        "options" => { kind: Bytes, derived: false, required: false, description: "Verbatim standard or unknown TCP options",
            get |layer| Some(reflect_get(&layer.options)), set |layer, value, name| reflect_set(&mut layer.options, tcp_schema(), name, value), layout: (20, header_len) },
        normalize |layer| { layer.checksum.normalize(); }
    }
    layout fn tcp_layout(header_len: usize);
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TcpCodec;

impl LayerCodec for TcpCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("tcp")
    }

    fn aliases(&self) -> &'static [&'static str] {
        super::super::support::aliases(self.protocol_id().as_str())
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
            if context.mode == crate::packet::build::BuildMode::Strict {
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
        let mut prefix = vec![0_u8; header_len];
        prefix[0..2].copy_from_slice(&layer.source_port.to_be_bytes());
        prefix[2..4].copy_from_slice(&layer.destination_port.to_be_bytes());
        prefix[4..8].copy_from_slice(&layer.sequence.to_be_bytes());
        prefix[8..12].copy_from_slice(&layer.acknowledgment.to_be_bytes());
        prefix[12] =
            (data_offset << 4) | ((layer.reserved_bits & 7) << 1) | ((layer.flags >> 8) as u8 & 1);
        prefix[13] = layer.flags as u8;
        prefix[14..16].copy_from_slice(&layer.window.to_be_bytes());
        prefix[18..20].copy_from_slice(&layer.urgent_pointer.to_be_bytes());
        prefix[20..].copy_from_slice(&options);
        let covered_payload = payload_without_padding("tcp", payload, context)?;
        let network = encode_network(context)?;
        let checksum_expected = transport_checksum_parts(network, 6, &[&prefix, covered_payload])?;
        let (checksum, materialized_checksum) = resolve_u16(
            "tcp",
            "checksum",
            &layer.checksum,
            ValueExpectation::Required(checksum_expected),
            context.mode,
            &mut diagnostics,
        )?;
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
        if context.verify_checksums
            && let Some(network) = context.network
            && transport_checksum(network, 6, input)? != 0
        {
            diagnostics.push(
                Diagnostic::warning("decode.tcp_checksum", "TCP checksum mismatch")
                    .at_field("checksum"),
            );
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
