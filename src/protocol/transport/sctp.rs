// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::sync::OnceLock;

use crate::packet::{
    build::BuildMode,
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    diagnostic::Diagnostic,
    field::{FieldKind, FieldValue, WireValue},
    layer::{FieldError, FieldSchema, Layer, LayerSchema, ProtocolId},
    registry::Discriminator,
};

use super::super::common::{
    ValueExpectation, aliased_fields, field_layout, impl_layer_boilerplate, invalid, make_layer,
    out_of_range, payload_without_padding, protocol, set_wire_u32, truncated, unknown_field,
    validate_dependent, wire_u32, wrong_layer, wrong_type,
};

const SCTP_HEADER_LEN: usize = 12;
const CHUNK_HEADER_LEN: usize = 4;
const CRC32C_POLYNOMIAL: u32 = 0x82f6_3b78;
const CRC32C_TABLE: [u32; 256] = crc32c_table();

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sctp {
    pub source_port: u16,
    pub destination_port: u16,
    pub verification_tag: u32,
    pub checksum: WireValue<u32>,
}

impl Default for Sctp {
    fn default() -> Self {
        Self {
            source_port: 50_000,
            destination_port: 5_000,
            verification_tag: 0,
            checksum: WireValue::Auto,
        }
    }
}

fn sctp_schema() -> &'static LayerSchema {
    static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
    static FIELDS: &[FieldSchema] = &[
        FieldSchema {
            name: "source_port",
            kind: FieldKind::Unsigned,
            derived: false,
            required: true,
            description: "SCTP source port",
        },
        FieldSchema {
            name: "destination_port",
            kind: FieldKind::Unsigned,
            derived: false,
            required: true,
            description: "SCTP destination port",
        },
        FieldSchema {
            name: "verification_tag",
            kind: FieldKind::Unsigned,
            derived: false,
            required: true,
            description: "SCTP verification tag",
        },
        FieldSchema {
            name: "checksum",
            kind: FieldKind::Unsigned,
            derived: true,
            required: false,
            description: "SCTP CRC32c checksum",
        },
    ];
    SCHEMA.get_or_init(|| LayerSchema {
        protocol: protocol("sctp"),
        name: "SCTP",
        fields: FIELDS,
    })
}

impl Layer for Sctp {
    impl_layer_boilerplate!(Sctp, sctp_schema);

    fn field(&self, name: &str) -> Option<FieldValue> {
        match name {
            "source_port" => Some(self.source_port.into()),
            "destination_port" => Some(self.destination_port.into()),
            "verification_tag" => Some(self.verification_tag.into()),
            "checksum" => Some(wire_u32(&self.checksum)),
            _ => None,
        }
    }

    fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), FieldError> {
        match (name, value) {
            ("source_port", FieldValue::Unsigned(value)) => {
                self.source_port =
                    u16::try_from(value).map_err(|_| out_of_range(sctp_schema(), name))?
            }
            ("destination_port", FieldValue::Unsigned(value)) => {
                self.destination_port =
                    u16::try_from(value).map_err(|_| out_of_range(sctp_schema(), name))?
            }
            ("verification_tag", FieldValue::Unsigned(value)) => {
                self.verification_tag =
                    u32::try_from(value).map_err(|_| out_of_range(sctp_schema(), name))?
            }
            ("checksum", value) => {
                return set_wire_u32(&mut self.checksum, sctp_schema(), name, value);
            }
            ("source_port" | "destination_port" | "verification_tag", _) => {
                return Err(wrong_type(sctp_schema(), name, "unsigned"));
            }
            _ => return Err(unknown_field(sctp_schema(), name)),
        }
        Ok(())
    }

    fn normalize(&mut self) {
        self.checksum.normalize();
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SctpCodec;

impl LayerCodec for SctpCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("sctp")
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
            .downcast_ref::<Sctp>()
            .ok_or_else(|| wrong_layer("sctp", layer))?;
        let mut diagnostics = Vec::new();
        validate_port("source_port", layer.source_port, context, &mut diagnostics)?;
        validate_port(
            "destination_port",
            layer.destination_port,
            context,
            &mut diagnostics,
        )?;

        let covered_payload = payload_without_padding("sctp", payload, context)?;
        if let Err(message) = validate_chunks(covered_payload, true) {
            if context.mode == BuildMode::Strict {
                return Err(invalid("sctp", message));
            }
            diagnostics.push(Diagnostic::warning("build.sctp_chunks", message));
        }

        let mut header = [0_u8; SCTP_HEADER_LEN];
        header[0..2].copy_from_slice(&layer.source_port.to_be_bytes());
        header[2..4].copy_from_slice(&layer.destination_port.to_be_bytes());
        header[4..8].copy_from_slice(&layer.verification_tag.to_be_bytes());
        let expected_checksum = crc32c_parts(&[&header, covered_payload]);
        let (checksum, materialized_checksum) = resolve_u32(
            "sctp",
            "checksum",
            &layer.checksum,
            ValueExpectation::Required(expected_checksum),
            context.mode,
            &mut diagnostics,
        )?;
        header[8..12].copy_from_slice(&checksum_to_wire(checksum));

        let mut materialized = layer.clone();
        materialized.checksum = materialized_checksum;
        Ok(EncodedLayer {
            prefix: header.to_vec(),
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: sctp_layout(),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < SCTP_HEADER_LEN {
            return Err(truncated("sctp", SCTP_HEADER_LEN, input.len()));
        }
        validate_chunks(&input[SCTP_HEADER_LEN..], false)
            .map_err(|message| invalid("sctp", message))?;

        let source_port = u16::from_be_bytes([input[0], input[1]]);
        let destination_port = u16::from_be_bytes([input[2], input[3]]);
        let checksum = checksum_from_wire([input[8], input[9], input[10], input[11]]);
        let mut diagnostics = Vec::new();
        if source_port == 0 {
            warn_zero_port(&mut diagnostics, "source_port", "source");
        }
        if destination_port == 0 {
            warn_zero_port(&mut diagnostics, "destination_port", "destination");
        }
        if context.verify_checksums {
            let zero_checksum = [0_u8; 4];
            let expected = crc32c_parts(&[&input[..8], &zero_checksum, &input[SCTP_HEADER_LEN..]]);
            if checksum != expected {
                diagnostics.push(
                    Diagnostic::warning("decode.sctp_checksum", "SCTP checksum mismatch")
                        .at_field("checksum"),
                );
            }
        }

        Ok(DecodedLayerValue {
            layer: Box::new(Sctp {
                source_port,
                destination_port,
                verification_tag: u32::from_be_bytes([input[4], input[5], input[6], input[7]]),
                checksum: WireValue::Exact(checksum),
            }),
            consumed: SCTP_HEADER_LEN,
            payload_offset: SCTP_HEADER_LEN,
            payload_len: input.len() - SCTP_HEADER_LEN,
            next: vec![Discriminator(0)],
            fields: sctp_layout(),
            diagnostics,
            stop: false,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(
            Sctp::default(),
            &aliased_fields(
                "sctp",
                fields,
                &[
                    ("sport", "source_port"),
                    ("dport", "destination_port"),
                    ("vtag", "verification_tag"),
                ],
            )?,
        )
    }
}

fn validate_port(
    field: &'static str,
    port: u16,
    context: &LayerEncodeContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), CodecError> {
    if port != 0 {
        return Ok(());
    }
    let message = format!("{} must not be zero", field.replace('_', " "));
    if context.mode == BuildMode::Strict {
        return Err(invalid("sctp", message));
    }
    diagnostics.push(Diagnostic::warning("build.sctp_zero_port", message).at_field(field));
    Ok(())
}

fn warn_zero_port(diagnostics: &mut Vec<Diagnostic>, field: &'static str, which: &'static str) {
    diagnostics.push(
        Diagnostic::warning(
            "decode.sctp_zero_port",
            format!("SCTP {which} port is zero"),
        )
        .at_field(field),
    );
}

fn validate_chunks(payload: &[u8], require_zero_padding: bool) -> Result<(), String> {
    if payload.is_empty() {
        return Err("packet must contain at least one SCTP chunk".to_owned());
    }

    let mut cursor = 0_usize;
    let mut chunk_count = 0_usize;
    let mut unbundleable = None;
    while cursor < payload.len() {
        let remaining = payload.len() - cursor;
        if remaining < CHUNK_HEADER_LEN {
            return Err(format!(
                "chunk at payload offset {cursor} has a truncated header ({remaining} byte(s) remain)"
            ));
        }

        let chunk_type = payload[cursor];
        let chunk_len = usize::from(u16::from_be_bytes([
            payload[cursor + 2],
            payload[cursor + 3],
        ]));
        if chunk_len < CHUNK_HEADER_LEN {
            return Err(format!(
                "chunk at payload offset {cursor} has length {chunk_len}, below {CHUNK_HEADER_LEN}"
            ));
        }
        if chunk_len > remaining {
            return Err(format!(
                "chunk at payload offset {cursor} declares {chunk_len} bytes, but only {remaining} remain"
            ));
        }

        let padded_len = chunk_len
            .checked_add(3)
            .map(|length| length & !3)
            .ok_or_else(|| format!("chunk length overflow at payload offset {cursor}"))?;
        if padded_len > remaining {
            return Err(format!(
                "chunk at payload offset {cursor} is missing {} byte(s) of alignment padding",
                padded_len - remaining
            ));
        }
        if require_zero_padding
            && payload[cursor + chunk_len..cursor + padded_len]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(format!(
                "chunk at payload offset {cursor} has non-zero alignment padding"
            ));
        }

        chunk_count += 1;
        if matches!(chunk_type, 1 | 2 | 14) {
            unbundleable = Some(chunk_type);
        }
        cursor += padded_len;
    }

    if chunk_count > 1
        && let Some(chunk_type) = unbundleable
    {
        let name = match chunk_type {
            1 => "INIT",
            2 => "INIT ACK",
            14 => "SHUTDOWN COMPLETE",
            _ => unreachable!("unbundleable chunk type was checked above"),
        };
        return Err(format!(
            "{name} chunk must not be bundled with other chunks"
        ));
    }
    Ok(())
}

fn sctp_layout() -> Vec<crate::packet::layout::FieldLayout> {
    vec![
        field_layout("source_port", 0, 2),
        field_layout("destination_port", 2, 4),
        field_layout("verification_tag", 4, 8),
        field_layout("checksum", 8, 12),
    ]
}

fn resolve_u32(
    name: &str,
    field: &str,
    value: &WireValue<u32>,
    expectation: ValueExpectation<u32>,
    mode: BuildMode,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(u32, WireValue<u32>), CodecError> {
    let expected = match expectation {
        ValueExpectation::Required(value) | ValueExpectation::Suggested(value) => value,
    };
    match value {
        WireValue::Auto => Ok((expected, WireValue::Exact(expected))),
        WireValue::Exact(actual) => {
            validate_dependent(name, field, *actual, expectation, mode, diagnostics)?;
            Ok((*actual, value.clone()))
        }
        WireValue::Raw(bytes) => {
            if mode == BuildMode::Strict {
                return Err(invalid(
                    name,
                    format!("raw {field} requires permissive build mode"),
                ));
            }
            let raw: [u8; 4] = bytes.as_ref().try_into().map_err(|_| {
                invalid(name, format!("raw {field} must contain exactly four bytes"))
            })?;
            diagnostics.push(
                Diagnostic::warning(
                    "build.raw_dependent_field",
                    format!("emitting raw {field} value"),
                )
                .at_field(field),
            );
            Ok((checksum_from_wire(raw), value.clone()))
        }
    }
}

const fn crc32c_table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut index = 0_usize;
    while index < table.len() {
        let mut remainder = index as u32;
        let mut bit = 0;
        while bit < 8 {
            remainder = if remainder & 1 == 0 {
                remainder >> 1
            } else {
                (remainder >> 1) ^ CRC32C_POLYNOMIAL
            };
            bit += 1;
        }
        table[index] = remainder;
        index += 1;
    }
    table
}

#[cfg(test)]
fn crc32c(bytes: &[u8]) -> u32 {
    crc32c_parts(&[bytes])
}

fn crc32c_parts(parts: &[&[u8]]) -> u32 {
    let mut remainder = u32::MAX;
    for part in parts {
        for byte in *part {
            let index = ((remainder ^ u32::from(*byte)) & 0xff) as usize;
            remainder = (remainder >> 8) ^ CRC32C_TABLE[index];
        }
    }
    !remainder
}

fn checksum_to_wire(checksum: u32) -> [u8; 4] {
    checksum.to_le_bytes()
}

fn checksum_from_wire(bytes: [u8; 4]) -> u32 {
    u32::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::{checksum_from_wire, checksum_to_wire, crc32c, crc32c_parts, validate_chunks};

    #[test]
    fn crc32c_matches_standard_check_value() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    }

    #[test]
    fn crc32c_parts_are_one_contiguous_stream() {
        assert_eq!(
            crc32c_parts(&[b"123", b"456", b"789"]),
            crc32c(b"123456789")
        );
    }

    #[test]
    fn checksum_uses_sctp_reflected_wire_order() {
        let checksum = 0xe306_9283;
        let wire = [0x83, 0x92, 0x06, 0xe3];
        assert_eq!(checksum_to_wire(checksum), wire);
        assert_eq!(checksum_from_wire(wire), checksum);
    }

    #[test]
    fn chunk_validation_accepts_aligned_and_padded_chunks() {
        assert!(validate_chunks(&[0, 0, 0, 4], true).is_ok());
        assert!(validate_chunks(&[0, 0, 0, 5, 0xaa, 0, 0, 0], true).is_ok());
    }

    #[test]
    fn chunk_validation_rejects_bad_lengths_and_missing_padding() {
        assert!(validate_chunks(&[0, 0, 0, 3], true).is_err());
        assert!(validate_chunks(&[0, 0, 0, 8], true).is_err());
        assert!(validate_chunks(&[0, 0, 0, 5, 0xaa], true).is_err());
        assert!(validate_chunks(&[0, 0, 0, 5, 0xaa, 1, 2, 3], true).is_err());
        assert!(validate_chunks(&[0, 0, 0, 5, 0xaa, 1, 2, 3], false).is_ok());
    }

    #[test]
    fn chunk_validation_rejects_unbundleable_chunks() {
        assert!(validate_chunks(&[1, 0, 0, 4, 0, 0, 0, 4], true).is_err());
        assert!(validate_chunks(&[0, 0, 0, 4, 2, 0, 0, 4], true).is_err());
        assert!(validate_chunks(&[14, 0, 0, 4, 0, 0, 0, 4], true).is_err());
    }
}
