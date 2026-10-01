// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::Diagnostic,
    field::{FieldValue, WireValue},
    layer::{Layer, reflective_layer},
    layout::{ByteRange, FieldLayout},
    registry::Discriminator,
};

use crate::protocol::common::{
    ValueExpectation, child_is_opaque, ensure_encode_budget, invalid, make_layer,
    payload_without_padding, protocol, resolve_u16, strict_or_diagnostic, truncated, typed_layer,
};

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::Gtpu.as_str();

const GTPU_BASE_LEN: usize = 8;
/// Sequence number, N-PDU number and next extension header type.
const GTPU_OPTIONAL_LEN: usize = 4;
const GTPU_VERSION: u8 = 1;
const VERSION_MAX: u8 = 0x07;
const GTPU_G_PDU: u8 = 0xff;
/// The walk stops after this many extension headers; real traffic carries a
/// handful at most.
const MAX_EXTENSION_HEADERS: usize = 16;
const EXTENSION_UNIT: usize = 4;

const FLAG_PROTOCOL_TYPE: u8 = 0x10;
const FLAG_RESERVED: u8 = 0x08;
const FLAG_EXTENSION: u8 = 0x04;
const FLAG_SEQUENCE: u8 = 0x02;
const FLAG_NPDU: u8 = 0x01;

/// G-PDU payloads select their IP version by the first payload nibble, the
/// technique MPLS uses below the bottom of its label stack.
pub(crate) const GTPU_IP_VERSION_BASE: u64 = 0x100;
pub(crate) const GTPU_OTHER_PAYLOAD: u64 = 0;

/// GTP-U v1 header (3GPP TS 29.281) on UDP port 2152.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gtpu {
    pub version: u8,
    /// PT: set for GTP, clear for GTP'.
    pub protocol_type: bool,
    pub reserved: bool,
    pub extension_flag: bool,
    pub sequence_flag: bool,
    pub npdu_flag: bool,
    pub message_type: u8,
    /// Bytes after the first eight, including optional fields and extensions.
    pub length: WireValue<u16>,
    pub teid: u32,
    pub sequence_number: u16,
    pub npdu_number: u8,
    pub next_extension_type: u8,
    /// Extension header chain kept verbatim, from the first length octet
    /// through the last next-type octet.
    pub extensions: Bytes,
}

impl Default for Gtpu {
    fn default() -> Self {
        Self {
            version: GTPU_VERSION,
            protocol_type: true,
            reserved: false,
            extension_flag: false,
            sequence_flag: false,
            npdu_flag: false,
            message_type: GTPU_G_PDU,
            length: WireValue::Auto,
            teid: 0,
            sequence_number: 0,
            npdu_number: 0,
            next_extension_type: 0,
            extensions: Bytes::new(),
        }
    }
}

impl Gtpu {
    fn has_optional_fields(&self) -> bool {
        self.extension_flag || self.sequence_flag || self.npdu_flag
    }
}

reflective_layer! {
    fn gtpu_schema() => { protocol: protocol(NAME), name: "GTP-U" }
    impl Gtpu {
        "version" => { kind: Unsigned, derived: false, required: false, description: "3-bit GTP version; GTP-U is version 1", reflect_bounded: version, VERSION_MAX, layout: (0, 1) },
        "protocol_type" => { kind: Bool, derived: false, required: false, description: "PT flag: set for GTP, clear for GTP'", reflect: protocol_type, layout: (0, 1) },
        "reserved" => { kind: Bool, derived: false, required: false, description: "Reserved flag bit, zero on transmission", reflect: reserved, layout: (0, 1) },
        "extension_flag" => { kind: Bool, derived: false, required: false, description: "E flag: an extension header chain follows", reflect: extension_flag, layout: (0, 1) },
        "sequence_flag" => { kind: Bool, derived: false, required: false, description: "S flag: the sequence number is meaningful", reflect: sequence_flag, layout: (0, 1) },
        "npdu_flag" => { kind: Bool, derived: false, required: false, description: "PN flag: the N-PDU number is meaningful", reflect: npdu_flag, layout: (0, 1) },
        "message_type" => { kind: Unsigned, derived: false, required: false, description: "Message type; 255 is a G-PDU carrying a user IP packet", reflect: message_type, layout: (1, 2) },
        "length" => { kind: Unsigned, derived: true, required: false, description: "Bytes after the first eight, including optional fields and extension headers", reflect: length, layout: (2, 4) },
        "teid" => { kind: Unsigned, derived: false, required: true, description: "Tunnel endpoint identifier", reflect: teid, layout: (4, 8) },
        "sequence_number" => { kind: Unsigned, derived: false, required: false, description: "Optional sequence number; on the wire when any of E, S or PN is set", reflect: sequence_number },
        "npdu_number" => { kind: Unsigned, derived: false, required: false, description: "Optional N-PDU number; on the wire when any of E, S or PN is set", reflect: npdu_number },
        "next_extension_type" => { kind: Unsigned, derived: false, required: false, description: "Type of the first extension header; on the wire when any of E, S or PN is set", reflect: next_extension_type },
        "extensions" => { kind: Bytes, derived: false, required: false, description: "Verbatim extension header chain", reflect: extensions }
    }
    layout fn gtpu_static_layout();
}

fn gtpu_layout(layer: &Gtpu) -> Vec<FieldLayout> {
    let mut fields = gtpu_static_layout();
    if layer.has_optional_fields() {
        fields.extend([
            FieldLayout {
                name: "sequence_number",
                range: ByteRange::new(8, 10),
            },
            FieldLayout {
                name: "npdu_number",
                range: ByteRange::new(10, 11),
            },
            FieldLayout {
                name: "next_extension_type",
                range: ByteRange::new(11, 12),
            },
        ]);
        if !layer.extensions.is_empty() {
            fields.push(FieldLayout {
                name: "extensions",
                range: ByteRange::new(
                    GTPU_BASE_LEN.saturating_add(GTPU_OPTIONAL_LEN),
                    GTPU_BASE_LEN
                        .saturating_add(GTPU_OPTIONAL_LEN)
                        .saturating_add(layer.extensions.len()),
                ),
            });
        }
    }
    fields
}

/// Walks a chain of extension headers, each a length octet counted in 4-byte
/// units (itself and the trailing next-type octet included), content, and the
/// next type; type 0 ends the chain. Returns the chain's byte length.
fn extension_chain_len(data: &[u8]) -> Result<usize, &'static str> {
    let mut cursor = 0_usize;
    for _ in 0..MAX_EXTENSION_HEADERS {
        let Some(&units) = data.get(cursor) else {
            return Err("extension header chain is truncated");
        };
        if units == 0 {
            return Err("extension header has zero length");
        }
        let end = usize::from(units)
            .checked_mul(EXTENSION_UNIT)
            .and_then(|length| cursor.checked_add(length))
            .ok_or("extension header length overflows")?;
        let Some(&next_type) = end.checked_sub(1).and_then(|last| data.get(last)) else {
            return Err("extension header runs past the declared length");
        };
        cursor = end;
        if next_type == 0 {
            return Ok(cursor);
        }
    }
    Err("extension header chain exceeds the supported header count")
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct GtpuCodec;

impl LayerCodec for GtpuCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &gtpu_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Gtpu>(NAME, layer)?;
        if layer.version > VERSION_MAX {
            return Err(invalid(NAME, "version exceeds its three-bit field"));
        }
        let covered_payload = payload_without_padding(NAME, payload, context)?;
        let optional_len = if layer.has_optional_fields() {
            GTPU_OPTIONAL_LEN
        } else {
            0
        };
        if !layer.extension_flag && !layer.extensions.is_empty() {
            return Err(invalid(
                NAME,
                "extension headers require the E flag; clear them or set extension_flag",
            ));
        }
        let header_extra = optional_len
            .checked_add(layer.extensions.len())
            .ok_or_else(|| invalid(NAME, "header length overflow"))?;
        let header_len = GTPU_BASE_LEN
            .checked_add(header_extra)
            .ok_or_else(|| invalid(NAME, "header length overflow"))?;
        ensure_encode_budget(NAME, header_len, context)?;
        let expected_length = header_extra
            .checked_add(covered_payload.len())
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| invalid(NAME, "message exceeds the GTP-U length range"))?;

        let mut diagnostics = Vec::new();
        validate_header(layer, context, &mut diagnostics)?;
        validate_child(layer, context, &mut diagnostics)?;
        let (length, materialized_length) = resolve_u16(
            NAME,
            "length",
            &layer.length,
            ValueExpectation::Required(expected_length),
            context.mode,
            &mut diagnostics,
        )?;

        let flags = (layer.version << 5)
            | if layer.protocol_type {
                FLAG_PROTOCOL_TYPE
            } else {
                0
            }
            | if layer.reserved { FLAG_RESERVED } else { 0 }
            | if layer.extension_flag {
                FLAG_EXTENSION
            } else {
                0
            }
            | if layer.sequence_flag {
                FLAG_SEQUENCE
            } else {
                0
            }
            | if layer.npdu_flag { FLAG_NPDU } else { 0 };
        let mut prefix = Vec::with_capacity(header_len);
        prefix.push(flags);
        prefix.push(layer.message_type);
        prefix.extend_from_slice(&length.to_be_bytes());
        prefix.extend_from_slice(&layer.teid.to_be_bytes());
        if optional_len != 0 {
            prefix.extend_from_slice(&layer.sequence_number.to_be_bytes());
            prefix.push(layer.npdu_number);
            prefix.push(layer.next_extension_type);
        }
        prefix.extend_from_slice(&layer.extensions);

        let mut materialized = layer.clone();
        materialized.length = materialized_length;
        Ok(EncodedLayer::header(prefix, Box::new(materialized))
            .with_fields(gtpu_layout(layer))
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let Some(header) = input.first_chunk::<GTPU_BASE_LEN>() else {
            return Err(truncated(NAME, GTPU_BASE_LEN, input.len()));
        };
        let flags = header[0];
        let length_field = u16::from_be_bytes([header[2], header[3]]);
        let declared_end = GTPU_BASE_LEN.saturating_add(usize::from(length_field));
        let Some(body) = input.get(GTPU_BASE_LEN..declared_end) else {
            return Err(truncated(NAME, declared_end, input.len()));
        };
        let mut layer = Gtpu {
            version: flags >> 5,
            protocol_type: flags & FLAG_PROTOCOL_TYPE != 0,
            reserved: flags & FLAG_RESERVED != 0,
            extension_flag: flags & FLAG_EXTENSION != 0,
            sequence_flag: flags & FLAG_SEQUENCE != 0,
            npdu_flag: flags & FLAG_NPDU != 0,
            message_type: header[1],
            length: WireValue::Exact(length_field),
            teid: u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
            sequence_number: 0,
            npdu_number: 0,
            next_extension_type: 0,
            extensions: Bytes::new(),
        };

        let mut diagnostics = Vec::new();
        if layer.version != GTPU_VERSION {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.gtpu_version",
                    "GTP version is not 1; the payload is preserved without typed dissection",
                )
                .at_field("version"),
            );
        }
        if !layer.protocol_type {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.gtpu_protocol_type",
                    "the PT flag is clear, so this is GTP' rather than GTP-U; the payload is preserved without typed dissection",
                )
                .at_field("protocol_type"),
            );
        }
        if layer.reserved {
            diagnostics.push(
                Diagnostic::warning("decode.gtpu_reserved", "the reserved GTP flag bit is set")
                    .at_field("reserved"),
            );
        }

        let mut header_len = GTPU_BASE_LEN;
        if layer.has_optional_fields() {
            let Some(optional) = body.first_chunk::<GTPU_OPTIONAL_LEN>() else {
                return Err(invalid(
                    NAME,
                    format!(
                        "length {length_field} is too short for the optional fields the E, S or PN flag announces"
                    ),
                ));
            };
            layer.sequence_number = u16::from_be_bytes([optional[0], optional[1]]);
            layer.npdu_number = optional[2];
            layer.next_extension_type = optional[3];
            header_len = header_len.saturating_add(GTPU_OPTIONAL_LEN);
            for (set, flag, field) in [
                (
                    layer.sequence_number != 0,
                    layer.sequence_flag,
                    "sequence_number",
                ),
                (layer.npdu_number != 0, layer.npdu_flag, "npdu_number"),
                (
                    layer.next_extension_type != 0,
                    layer.extension_flag,
                    "next_extension_type",
                ),
            ] {
                if set && !flag {
                    diagnostics.push(
                        Diagnostic::warning(
                            "decode.gtpu_flags",
                            format!("{field} is non-zero but its flag is clear"),
                        )
                        .at_field(field),
                    );
                }
            }
            if layer.extension_flag && layer.next_extension_type != 0 {
                let chain = body.get(GTPU_OPTIONAL_LEN..).unwrap_or_default();
                let chain_len =
                    extension_chain_len(chain).map_err(|reason| invalid(NAME, reason))?;
                layer.extensions = input.slice(header_len..header_len.saturating_add(chain_len));
                header_len = header_len.saturating_add(chain_len);
            }
        }

        let payload_len = declared_end.saturating_sub(header_len);
        let first = input.get(header_len..declared_end).and_then(<[u8]>::first);
        let selects_ip = layer.version == GTPU_VERSION
            && layer.protocol_type
            && layer.message_type == GTPU_G_PDU;
        let next = match first {
            Some(&first) if selects_ip => vec![
                Discriminator(GTPU_IP_VERSION_BASE.saturating_add(u64::from(first >> 4))),
                Discriminator(GTPU_OTHER_PAYLOAD),
            ],
            _ => vec![Discriminator(GTPU_OTHER_PAYLOAD)],
        };
        Ok(DecodedLayer {
            fields: gtpu_layout(&layer),
            layer: Box::new(layer),
            consumed: header_len,
            payload_len,
            next,
            diagnostics,
            stop: payload_len == 0,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Gtpu::default(), fields)
    }
}

fn validate_header(
    layer: &Gtpu,
    context: &LayerEncodeContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), crate::codec::Error> {
    if layer.version != GTPU_VERSION {
        strict_or_diagnostic(
            NAME,
            "build.gtpu_version",
            "version",
            "GTP-U is version 1",
            context,
            diagnostics,
        )?;
    }
    if !layer.protocol_type {
        strict_or_diagnostic(
            NAME,
            "build.gtpu_protocol_type",
            "protocol_type",
            "a clear PT flag selects GTP', not GTP-U",
            context,
            diagnostics,
        )?;
    }
    if layer.reserved {
        strict_or_diagnostic(
            NAME,
            "build.gtpu_reserved",
            "reserved",
            "the reserved GTP flag bit must be zero on transmission",
            context,
            diagnostics,
        )?;
    }
    for (set, flag, field) in [
        (
            layer.sequence_number != 0,
            layer.sequence_flag,
            "sequence_number",
        ),
        (layer.npdu_number != 0, layer.npdu_flag, "npdu_number"),
        (
            layer.next_extension_type != 0,
            layer.extension_flag,
            "next_extension_type",
        ),
    ] {
        if set && !flag {
            strict_or_diagnostic(
                NAME,
                "build.gtpu_flags",
                field,
                format!("{field} is set but its flag is clear, so a receiver ignores it"),
                context,
                diagnostics,
            )?;
        }
    }
    if layer.extension_flag {
        let chain = if layer.extensions.is_empty() {
            layer.next_extension_type == 0
        } else {
            layer.next_extension_type != 0
                && extension_chain_len(&layer.extensions) == Ok(layer.extensions.len())
        };
        if !chain {
            strict_or_diagnostic(
                NAME,
                "build.gtpu_extension",
                "extensions",
                "next_extension_type and the extension bytes must describe one terminated header chain",
                context,
                diagnostics,
            )?;
        }
    }
    Ok(())
}

/// Only a G-PDU carries a user IP packet; every other message type keeps its
/// information elements as opaque bytes.
fn validate_child(
    layer: &Gtpu,
    context: &LayerEncodeContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), crate::codec::Error> {
    let Some(child) = context.child else {
        return Ok(());
    };
    if child_is_opaque(child) {
        return Ok(());
    }
    let carries_ip = layer.message_type == GTPU_G_PDU
        && matches!(
            BuiltinProtocol::of(child),
            Some(BuiltinProtocol::Ipv4 | BuiltinProtocol::Ipv6)
        );
    if carries_ip {
        return Ok(());
    }
    strict_or_diagnostic(
        NAME,
        "build.gtpu_payload",
        "message_type",
        format!(
            "message type {} does not carry a typed {} child; only a G-PDU (255) carries IPv4 or IPv6",
            layer.message_type,
            child.protocol_id()
        ),
        context,
        diagnostics,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_chain_walk_is_bounded_and_rejects_zero_length() {
        // one header of two units whose next type is zero
        assert_eq!(
            extension_chain_len(&[2, 0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0]),
            Ok(8)
        );
        // a zero length would never advance the cursor
        assert_eq!(
            extension_chain_len(&[0, 0, 0, 0]),
            Err("extension header has zero length")
        );
        // a header claiming more bytes than remain
        assert_eq!(
            extension_chain_len(&[2, 0, 0, 0]),
            Err("extension header runs past the declared length")
        );
        // a chain that never terminates stops at the header cap
        let endless = [1_u8, 0, 0, 0xc0].repeat(MAX_EXTENSION_HEADERS + 1);
        assert_eq!(
            extension_chain_len(&endless),
            Err("extension header chain exceeds the supported header count")
        );
        // a chain cut off after a non-final header
        assert_eq!(
            extension_chain_len(&[1, 0, 0, 0xc0]),
            Err("extension header chain is truncated")
        );
    }
}
