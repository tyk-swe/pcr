// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! TCP segment model and codec.

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::{Diagnostic, TCP_CHECKSUM},
    field::{FieldValue, WireValue},
    layer::{Layer, reflective_layer},
};

use super::ports::child_discriminators;
use crate::protocol::common::{
    ValueExpectation, invalid, make_layer, payload_without_padding, protocol, resolve_u16,
    transport_checksum, transport_checksum_parts, truncated, typed_layer,
};
use crate::protocol::network::{ip_protocol, resolve_envelope};

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::Tcp.as_str();

const TCP_MIN_LEN: usize = 20;

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
    pub const ACK: u16 = 0x010;
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
    fn tcp_schema() => { protocol: protocol(NAME), name: "TCP" }
    impl Tcp {
        "source_port" | "sport" => { kind: Unsigned, derived: false, required: true, description: "TCP source port",
            reflect: source_port, layout: (0, 2) },
        "destination_port" | "dport" => { kind: Unsigned, derived: false, required: true, description: "TCP destination port",
            reflect: destination_port, layout: (2, 4) },
        "sequence" => { kind: Unsigned, derived: false, required: true, description: "Sequence number",
            reflect: sequence, layout: (4, 8) },
        "acknowledgment" => { kind: Unsigned, derived: false, required: false, description: "Acknowledgment number",
            reflect: acknowledgment, layout: (8, 12) },
        "reserved_bits" => { kind: Unsigned, derived: false, required: false, description: "Three reserved TCP header bits",
            reflect_bounded: reserved_bits, 7_u64, layout: (12, 13) },
        "flags" => { kind: Unsigned, derived: false, required: true, description: "Nine TCP control flags",
            reflect_bounded: flags, 0x01ff_u64, layout: (12, 14) },
        "window" => { kind: Unsigned, derived: false, required: true, description: "Receive window",
            reflect: window, layout: (14, 16) },
        "checksum" => { kind: Unsigned, derived: true, required: false, description: "TCP checksum",
            reflect: checksum, layout: (16, 18) },
        "urgent_pointer" => { kind: Unsigned, derived: false, required: false, description: "Urgent pointer",
            reflect: urgent_pointer, layout: (18, 20) },
        "options" => { kind: Bytes, derived: false, required: false, description: "Verbatim standard or unknown TCP options",
            reflect: options, layout: (20, header_len) },
    }
    layout pub(crate) fn tcp_layout(header_len: usize);
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TcpCodec;

impl LayerCodec for TcpCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &tcp_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Tcp>(NAME, layer)?;
        if layer.flags > 0x01ff {
            return Err(invalid(NAME, "flags exceed nine bits"));
        }
        if layer.reserved_bits > 7 {
            return Err(invalid(NAME, "reserved bits exceed three bits"));
        }
        if layer.options.len() > 40 {
            return Err(invalid(NAME, "options exceed the 40-byte TCP limit"));
        }
        let mut diagnostics = Vec::new();
        if layer.reserved_bits != 0 {
            let message = "reserved TCP header bits are non-zero";
            if context.mode == crate::codec::Mode::Strict {
                return Err(invalid(NAME, message));
            }
            diagnostics.push(
                Diagnostic::warning("build.tcp_reserved_bits", message).at_field("reserved_bits"),
            );
        }
        let mut options = layer.options.to_vec();
        let padding = 4_usize.saturating_sub(options.len() % 4) % 4;
        if padding != 0 {
            options.resize(options.len().saturating_add(padding), 0);
            diagnostics.push(
                Diagnostic::warning(
                    "build.tcp_options_padded",
                    format!("padded TCP options with {padding} zero byte(s)"),
                )
                .at_field("options"),
            );
        }
        let header_len = TCP_MIN_LEN.saturating_add(options.len());
        let data_offset =
            u8::try_from(header_len / 4).map_err(|_| invalid(NAME, "header length overflow"))?;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the 9-bit flags field is split deliberately: bit 8 goes into the byte at \
                      offset 12 below and the low 8 bits are this byte"
        )]
        let flags_low = layer.flags as u8;
        let mut prefix = Vec::with_capacity(header_len);
        prefix.extend_from_slice(&layer.source_port.to_be_bytes());
        prefix.extend_from_slice(&layer.destination_port.to_be_bytes());
        prefix.extend_from_slice(&layer.sequence.to_be_bytes());
        prefix.extend_from_slice(&layer.acknowledgment.to_be_bytes());
        prefix.push(
            (data_offset << 4) | ((layer.reserved_bits & 7) << 1) | ((layer.flags >> 8) as u8 & 1),
        );
        prefix.push(flags_low);
        prefix.extend_from_slice(&layer.window.to_be_bytes());
        // The checksum bytes stay zero while the segment checksum is computed.
        prefix.extend_from_slice(&[0, 0]);
        prefix.extend_from_slice(&layer.urgent_pointer.to_be_bytes());
        prefix.extend_from_slice(&options);
        let covered_payload = payload_without_padding(NAME, payload, context)?;
        let network = resolve_envelope(NAME, context)?;
        let checksum_expected =
            transport_checksum_parts(NAME, network, ip_protocol::TCP, &[&prefix, covered_payload])?;
        let (checksum, materialized_checksum) = resolve_u16(
            NAME,
            "checksum",
            &layer.checksum,
            ValueExpectation::Required(checksum_expected),
            context.mode,
            &mut diagnostics,
        )?;
        #[expect(
            clippy::indexing_slicing,
            reason = "the fixed twenty-byte prefix above always reserves bytes 16..18 for the checksum"
        )]
        {
            prefix[16..18].copy_from_slice(&checksum.to_be_bytes());
        }
        let mut materialized = layer.clone();
        materialized.checksum = materialized_checksum;
        materialized.options = Bytes::from(options);
        Ok(EncodedLayer::header(prefix, Box::new(materialized))
            .with_fields(tcp_layout(header_len))
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let Some(header) = input.first_chunk::<TCP_MIN_LEN>() else {
            return Err(truncated(NAME, TCP_MIN_LEN, input.len()));
        };
        let data_offset = usize::from(header[12] >> 4);
        if data_offset < 5 {
            return Err(invalid(
                NAME,
                format!("data offset {data_offset} is below 5"),
            ));
        }
        let header_len = data_offset
            .checked_mul(4)
            .ok_or_else(|| invalid(NAME, "data offset overflow"))?;
        let Some(options) = input.get(TCP_MIN_LEN..header_len) else {
            return Err(truncated(NAME, header_len, input.len()));
        };
        let checksum_value = u16::from_be_bytes([header[16], header[17]]);
        let mut diagnostics = Vec::new();
        let reserved_bits = (header[12] >> 1) & 7;
        if reserved_bits != 0 {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.tcp_reserved_bits",
                    "reserved TCP header bits are non-zero",
                )
                .at_field("reserved_bits"),
            );
        }
        if let Some(network) = context.network
            && transport_checksum(NAME, network, ip_protocol::TCP, input)? != 0
        {
            diagnostics.push(
                Diagnostic::warning(TCP_CHECKSUM, "TCP checksum mismatch").at_field("checksum"),
            );
        }
        let payload_len = input.len().saturating_sub(header_len);
        let source_port = u16::from_be_bytes([header[0], header[1]]);
        let destination_port = u16::from_be_bytes([header[2], header[3]]);
        Ok(DecodedLayer {
            layer: Box::new(Tcp {
                source_port,
                destination_port,
                sequence: u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
                acknowledgment: u32::from_be_bytes([header[8], header[9], header[10], header[11]]),
                reserved_bits,
                flags: (u16::from(header[12] & 1) << 8) | u16::from(header[13]),
                window: u16::from_be_bytes([header[14], header[15]]),
                checksum: WireValue::Exact(checksum_value),
                urgent_pointer: u16::from_be_bytes([header[18], header[19]]),
                options: Bytes::copy_from_slice(options),
            }),
            consumed: header_len,
            payload_len,
            // Both endpoints are offered before the raw fallback, exactly as
            // UDP does, so a payload protocol bound to a well-known TCP port
            // dissects in either direction. Unlike UDP there is no content
            // preference between them: a TLS segment looks the same in both
            // directions and the codec gates on the payload itself.
            next: if payload_len == 0 {
                Vec::new()
            } else {
                child_discriminators([destination_port, source_port])
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
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Tcp::default(), fields)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use super::child_discriminators;
    use crate::registry::Discriminator;

    fn ports(source_port: u16, destination_port: u16) -> Vec<u64> {
        child_discriminators([destination_port, source_port])
            .into_iter()
            .map(|Discriminator(value)| value)
            .collect()
    }

    #[test]
    fn the_destination_port_is_offered_before_the_source_port_and_the_fallback() {
        assert_eq!(ports(40_000, 443), vec![443, 40_000, 0]);
    }

    #[test]
    fn a_repeated_port_is_offered_once() {
        assert_eq!(ports(443, 443), vec![443, 0]);
    }

    #[test]
    fn a_zero_port_never_shadows_the_raw_fallback() {
        assert_eq!(ports(0, 0), vec![0]);
    }
}
