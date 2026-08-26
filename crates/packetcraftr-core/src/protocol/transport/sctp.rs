// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use crate::{
    codec::{DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::{Diagnostic, SCTP_CHECKSUM},
    field::{FieldValue, WireValue},
    layer::{Layer, reflective_layer},
    registry::Discriminator,
};

use super::super::common::{
    ValueExpectation, aliased_fields, invalid, make_layer, payload_without_padding, protocol,
    resolve_fixed, truncated, wrong_layer,
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

reflective_layer! {
    fn sctp_schema() => { protocol: protocol("sctp"), name: "SCTP" }
    impl Sctp {
        "source_port" => {
            kind: Unsigned, derived: false, required: true, description: "SCTP source port",
            reflect: source_port,
            layout: (0, 2)
        },
        "destination_port" => {
            kind: Unsigned, derived: false, required: true, description: "SCTP destination port",
            reflect: destination_port,
            layout: (2, 4)
        },
        "verification_tag" => {
            kind: Unsigned, derived: false, required: true, description: "SCTP verification tag",
            reflect: verification_tag,
            layout: (4, 8)
        },
        "checksum" => {
            kind: Unsigned, derived: true, required: false, description: "SCTP CRC32c checksum",
            reflect: checksum,
            layout: (8, 12)
        },
    }
    layout pub(crate) fn sctp_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SctpCodec;

impl LayerCodec for SctpCodec {
    fn protocol_id(&self) -> crate::layer::Id {
        protocol("sctp")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
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
            if context.mode == crate::build::Mode::Strict {
                return Err(invalid("sctp", message));
            }
            diagnostics.push(Diagnostic::warning("build.sctp_chunks", message));
        }

        let mut header = [0_u8; SCTP_HEADER_LEN];
        header[0..2].copy_from_slice(&layer.source_port.to_be_bytes());
        header[2..4].copy_from_slice(&layer.destination_port.to_be_bytes());
        header[4..8].copy_from_slice(&layer.verification_tag.to_be_bytes());
        let expected_checksum = crc32c_parts(&[&header, covered_payload]);
        let (checksum, materialized_checksum) = resolve_fixed(
            "sctp",
            "checksum",
            &layer.checksum,
            ValueExpectation::Required(expected_checksum),
            context.mode,
            &mut diagnostics,
            u32::from_le_bytes,
        )?;
        header[8..12].copy_from_slice(&checksum.to_le_bytes());

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
    ) -> Result<DecodedLayerValue, crate::codec::Error> {
        let Some(header) = input.first_chunk::<SCTP_HEADER_LEN>() else {
            return Err(truncated("sctp", SCTP_HEADER_LEN, input.len()));
        };
        let chunks = input.get(SCTP_HEADER_LEN..).unwrap_or_default();
        validate_chunks(chunks, false).map_err(|message| invalid("sctp", message))?;

        let source_port = u16::from_be_bytes([header[0], header[1]]);
        let destination_port = u16::from_be_bytes([header[2], header[3]]);
        let checksum = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
        let mut diagnostics = Vec::new();
        if source_port == 0 {
            warn_zero_port(&mut diagnostics, "source_port", "source");
        }
        if destination_port == 0 {
            warn_zero_port(&mut diagnostics, "destination_port", "destination");
        }
        if context.verify_checksums {
            let zero_checksum = [0_u8; 4];
            let before_checksum = header.get(..8).unwrap_or_default();
            let expected = crc32c_parts(&[before_checksum, &zero_checksum, chunks]);
            if checksum != expected {
                diagnostics.push(
                    Diagnostic::warning(SCTP_CHECKSUM, "SCTP checksum mismatch")
                        .at_field("checksum"),
                );
            }
        }

        Ok(DecodedLayerValue {
            layer: Box::new(Sctp {
                source_port,
                destination_port,
                verification_tag: u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
                checksum: WireValue::Exact(checksum),
            }),
            consumed: SCTP_HEADER_LEN,
            payload_len: input.len().saturating_sub(SCTP_HEADER_LEN),
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
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
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
) -> Result<(), crate::codec::Error> {
    if port != 0 {
        return Ok(());
    }
    let message = format!("{} must not be zero", field.replace('_', " "));
    if context.mode == crate::build::Mode::Strict {
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
        let remaining = payload.len().saturating_sub(cursor);
        let Some(chunk_header) = payload
            .get(cursor..)
            .and_then(<[u8]>::first_chunk::<CHUNK_HEADER_LEN>)
        else {
            return Err(format!(
                "chunk at payload offset {cursor} has a truncated header ({remaining} byte(s) remain)"
            ));
        };

        let chunk_type = chunk_header[0];
        let chunk_len = usize::from(u16::from_be_bytes([chunk_header[2], chunk_header[3]]));
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
                padded_len.saturating_sub(remaining)
            ));
        }
        let padding_start = cursor.saturating_add(chunk_len);
        let padding_end = cursor.saturating_add(padded_len);
        if require_zero_padding
            && payload
                .get(padding_start..padding_end)
                .is_some_and(|padding| padding.iter().any(|byte| *byte != 0))
        {
            return Err(format!(
                "chunk at payload offset {cursor} has non-zero alignment padding"
            ));
        }

        chunk_count = chunk_count.saturating_add(1);
        if matches!(chunk_type, 1 | 2 | 14) {
            unbundleable = Some(chunk_type);
        }
        cursor = cursor.saturating_add(padded_len);
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

const fn crc32c_table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut index = 0_usize;
    while index < table.len() {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the loop condition bounds index by table.len(), which is 256"
        )]
        let mut remainder = index as u32;
        let mut bit = 0_u32;
        while bit < 8 {
            remainder = if remainder & 1 == 0 {
                remainder >> 1
            } else {
                (remainder >> 1) ^ CRC32C_POLYNOMIAL
            };
            bit = bit.saturating_add(1);
        }
        #[expect(
            clippy::indexing_slicing,
            reason = "the while condition bounds index below table.len()"
        )]
        {
            table[index] = remainder;
        }
        index = index.saturating_add(1);
    }
    table
}

fn crc32c_parts(parts: &[&[u8]]) -> u32 {
    let mut remainder = u32::MAX;
    for part in parts {
        for byte in *part {
            let index = ((remainder ^ u32::from(*byte)) & 0xff) as usize;
            #[expect(
                clippy::indexing_slicing,
                reason = "the 0xff mask bounds index below 256, the length of CRC32C_TABLE"
            )]
            let entry = CRC32C_TABLE[index];
            remainder = (remainder >> 8) ^ entry;
        }
    }
    !remainder
}
