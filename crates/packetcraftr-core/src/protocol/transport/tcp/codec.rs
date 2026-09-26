// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use super::model::{
    KIND_END, KIND_MSS, KIND_NOP, KIND_SACK, KIND_SACK_PERMITTED, KIND_TIMESTAMPS,
    KIND_WINDOW_SCALE,
};
use super::reflection::{tcp_layout, tcp_schema};
use super::{SackBlock, Tcp, TcpOption};
use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::{Diagnostic, TCP_CHECKSUM},
    field::{FieldValue, WireValue},
    layer::Layer,
    protocol::{
        BuiltinProtocol,
        common::{
            ValueExpectation, invalid, make_layer, pad_options_to_four_bytes,
            payload_without_padding, resolve_u16, transport_checksum, transport_checksum_parts,
            truncated, typed_layer,
        },
        network::{ip_protocol, resolve_envelope},
        transport::ports::child_discriminators,
    },
};

pub(super) const NAME: &str = BuiltinProtocol::Tcp.as_str();

const TCP_MIN_LEN: usize = 20;

/// The option area the four-bit TCP data offset can address.
pub(super) const MAX_OPTION_BYTES: usize = 40;

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
        let serialized = serialize(&layer.options)?;
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
        let options = pad_options_to_four_bytes(
            &serialized,
            "build.tcp_options_padded",
            "TCP",
            &mut diagnostics,
        );
        let header_len = TCP_MIN_LEN.saturating_add(options.len());
        let data_offset =
            u8::try_from(header_len / 4).map_err(|_| invalid(NAME, "header length overflow"))?;
        // the 9-bit flags field is split deliberately: bit 8 goes into the byte at offset 12 below
        // and the low 8 bits are this byte
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
        // the fixed twenty-byte prefix above always reserves bytes 16..18 for the checksum
        {
            prefix[16..18].copy_from_slice(&checksum.to_be_bytes());
        }
        let mut materialized = layer.clone();
        materialized.checksum = materialized_checksum;
        materialized.options = parse(&Bytes::copy_from_slice(&options));
        Ok(EncodedLayer::header(prefix, Box::new(materialized))
            .with_fields(tcp_layout(header_len))
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: Bytes,
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
            && transport_checksum(NAME, network, ip_protocol::TCP, &input)? != 0
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
                options: parse(&input.slice_ref(options)),
            }),
            consumed: header_len,
            payload_len,
            // Both endpoints are offered before the raw fallback so a payload
            // protocol bound to a well-known TCP port dissects in either
            // direction. Unlike UDP there is no content preference between
            // them: a TLS segment looks the same in both directions and the
            // codec gates on the payload itself.
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

impl TcpOption {
    fn serialize(&self, output: &mut Vec<u8>) -> Result<(), crate::codec::Error> {
        let invalid = |message: &str| invalid(NAME, message);
        match self {
            Self::End => output.push(KIND_END),
            Self::Nop => output.push(KIND_NOP),
            Self::Mss(value) => {
                output.extend_from_slice(&[KIND_MSS, 4]);
                output.extend_from_slice(&value.to_be_bytes());
            }
            Self::WindowScale(shift) => {
                output.extend_from_slice(&[KIND_WINDOW_SCALE, 3, *shift]);
            }
            Self::SackPermitted => output.extend_from_slice(&[KIND_SACK_PERMITTED, 2]),
            Self::Sack(blocks) => {
                let body = blocks
                    .len()
                    .checked_mul(8)
                    .ok_or_else(|| invalid("SACK block count overflows the option length"))?;
                let length = body
                    .checked_add(2)
                    .ok_or_else(|| invalid("SACK block count overflows the option length"))?;
                let length = u8::try_from(length)
                    .map_err(|_| invalid("SACK blocks exceed the option length byte"))?;
                output.extend_from_slice(&[KIND_SACK, length]);
                for block in blocks {
                    output.extend_from_slice(&block.left_edge.to_be_bytes());
                    output.extend_from_slice(&block.right_edge.to_be_bytes());
                }
            }
            Self::Timestamps { value, echo_reply } => {
                output.extend_from_slice(&[KIND_TIMESTAMPS, 10]);
                output.extend_from_slice(&value.to_be_bytes());
                output.extend_from_slice(&echo_reply.to_be_bytes());
            }
            Self::Raw { kind, data } => {
                if matches!(*kind, KIND_END | KIND_NOP) {
                    return Err(invalid(
                        "raw option data cannot use the single-byte kinds 0 or 1",
                    ));
                }
                let length = data
                    .len()
                    .checked_add(2)
                    .ok_or_else(|| invalid("raw option length overflows"))?;
                let length = u8::try_from(length)
                    .map_err(|_| invalid("raw option data exceeds the length byte"))?;
                output.extend_from_slice(&[*kind, length]);
                output.extend_from_slice(data);
            }
            Self::Trailing(bytes) => output.extend_from_slice(bytes),
        }
        Ok(())
    }
}

/// Serializes options in order into the TCP option area (at most 40 bytes).
pub(super) fn serialize(options: &[TcpOption]) -> Result<Vec<u8>, crate::codec::Error> {
    let invalid = |message: &str| invalid(NAME, message);
    let mut output = Vec::with_capacity(MAX_OPTION_BYTES);
    let mut seen_end = false;
    let mut seen_trailing = false;
    for option in options {
        if seen_trailing || (seen_end && !matches!(option, TcpOption::Trailing(_))) {
            return Err(invalid(
                "only trailing bytes may follow the end of the option list",
            ));
        }
        let length = match option {
            TcpOption::End | TcpOption::Nop => Some(1),
            TcpOption::Mss(_) => Some(4),
            TcpOption::WindowScale(_) => Some(3),
            TcpOption::SackPermitted => Some(2),
            TcpOption::Sack(blocks) => {
                if blocks.is_empty() {
                    return Err(invalid("a typed SACK option requires at least one block"));
                }
                blocks
                    .len()
                    .checked_mul(8)
                    .and_then(|bytes| bytes.checked_add(2))
            }
            TcpOption::Timestamps { .. } => Some(10),
            TcpOption::Raw { data, .. } => data.len().checked_add(2),
            TcpOption::Trailing(bytes) => Some(bytes.len()),
        };
        if length.is_none_or(|length| length > MAX_OPTION_BYTES - output.len()) {
            return Err(invalid("options exceed the 40-byte TCP limit"));
        }
        option.serialize(&mut output)?;
        seen_end |= matches!(option, TcpOption::End);
        seen_trailing = matches!(option, TcpOption::Trailing(_));
    }
    Ok(output)
}

/// Parses the option area, preserving order and every byte. Input is already
/// bounded by the 40-byte TCP maximum, so parsing cannot allocate beyond it.
pub(super) fn parse(bytes: &Bytes) -> Vec<TcpOption> {
    let mut options = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        let kind = bytes[cursor];
        match kind {
            KIND_END => {
                options.push(TcpOption::End);
                if cursor + 1 < bytes.len() {
                    options.push(TcpOption::Trailing(bytes.slice(cursor + 1..)));
                }
                break;
            }
            KIND_NOP => {
                options.push(TcpOption::Nop);
                cursor += 1;
            }
            _ => {
                let malformed = || TcpOption::Trailing(bytes.slice(cursor..));
                let Some(&length) = bytes.get(cursor + 1) else {
                    options.push(malformed());
                    break;
                };
                let length = usize::from(length);
                let Some(body) = (length >= 2)
                    .then(|| bytes.get(cursor + 2..cursor + length))
                    .flatten()
                else {
                    options.push(malformed());
                    break;
                };
                options.push(typed(kind, bytes.slice_ref(body)));
                cursor += length;
            }
        }
    }
    options
}

/// Maps a well-formed TLV onto its typed variant; nonstandard lengths and
/// unknown kinds stay raw.
fn typed(kind: u8, body: Bytes) -> TcpOption {
    match (kind, body.as_ref()) {
        (KIND_MSS, [hi, lo]) => TcpOption::Mss(u16::from_be_bytes([*hi, *lo])),
        (KIND_WINDOW_SCALE, [shift]) => TcpOption::WindowScale(*shift),
        (KIND_SACK_PERMITTED, []) => TcpOption::SackPermitted,
        (KIND_SACK, blocks) if !blocks.is_empty() && blocks.len() % 8 == 0 => TcpOption::Sack(
            blocks
                .as_chunks::<8>()
                .0
                .iter()
                .map(|&[a, b, c, d, e, f, g, h]| SackBlock {
                    left_edge: u32::from_be_bytes([a, b, c, d]),
                    right_edge: u32::from_be_bytes([e, f, g, h]),
                })
                .collect(),
        ),
        (KIND_TIMESTAMPS, [a, b, c, d, e, f, g, h]) => TcpOption::Timestamps {
            value: u32::from_be_bytes([*a, *b, *c, *d]),
            echo_reply: u32::from_be_bytes([*e, *f, *g, *h]),
        },
        _ => TcpOption::Raw { kind, data: body },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Discriminator;

    fn wire(options: &[TcpOption]) -> Vec<u8> {
        serialize(options).expect("options serialize")
    }

    #[test]
    fn typed_options_round_trip_and_preserve_every_byte() {
        let options = vec![
            TcpOption::Mss(1460),
            TcpOption::SackPermitted,
            TcpOption::Timestamps {
                value: 0x01020304,
                echo_reply: 0xa0b0c0d0,
            },
            TcpOption::Nop,
            TcpOption::WindowScale(7),
            TcpOption::End,
            TcpOption::Trailing(Bytes::from_static(&[0x1e])),
        ];
        let bytes = wire(&options);
        assert_eq!(
            bytes,
            vec![
                2, 4, 0x05, 0xb4, 4, 2, 8, 10, 1, 2, 3, 4, 0xa0, 0xb0, 0xc0, 0xd0, 1, 3, 3, 7, 0,
                0x1e
            ]
        );
        assert_eq!(parse(&Bytes::copy_from_slice(&bytes)), options);
    }

    #[test]
    fn malformed_tails_and_unknown_kinds_stay_byte_exact() {
        // A missing length byte, a length below two, and a length that runs
        // past the option area each end option parsing; every byte is
        // retained verbatim and re-serializes identically.
        for bytes in [
            vec![1, 1, 2],
            vec![2, 1, 0xff],
            vec![2, 8, 0x05, 0xb4],
            vec![30, 4, 9, 9],
        ] {
            let parsed = parse(&Bytes::copy_from_slice(&bytes));
            assert!(matches!(
                parsed.last(),
                Some(TcpOption::Trailing(_)) | Some(TcpOption::Raw { .. })
            ));
            assert_eq!(wire(&parsed), bytes, "{bytes:?} must round-trip");
        }
        // The unparseable tail keeps the full malformed remainder.
        match parse(&Bytes::from_static(&[2, 8, 0x05, 0xb4])).as_slice() {
            [TcpOption::Trailing(bytes)] => assert_eq!(bytes.as_ref(), &[2, 8, 0x05, 0xb4]),
            other => panic!("expected trailing bytes, got {other:?}"),
        }
        // Padding after EOL is opaque, not additional options.
        assert_eq!(
            parse(&Bytes::from_static(&[0, 0, 0])),
            vec![
                TcpOption::End,
                TcpOption::Trailing(Bytes::from_static(&[0, 0])),
            ]
        );
    }

    #[test]
    fn eol_hides_tlv_shaped_padding_without_losing_bytes() {
        let bytes = [0, 2, 4, 0x05, 0xb4, 3, 3, 7];
        let parsed = parse(&Bytes::copy_from_slice(&bytes));
        assert_eq!(
            parsed,
            vec![
                TcpOption::End,
                TcpOption::Trailing(Bytes::copy_from_slice(&bytes[1..])),
            ]
        );
        assert_eq!(wire(&parsed), bytes);
        assert!(serialize(&[TcpOption::End, TcpOption::Mss(1460)]).is_err());
    }

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
