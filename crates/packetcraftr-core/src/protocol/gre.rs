// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Generic Routing Encapsulation protocol model.

use std::collections::BTreeMap;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::{Diagnostic, GRE_CHECKSUM},
    field::{FieldValue, WireValue},
    layer::{Layer, reflect_get, reflect_set, reflective_layer},
    registry::Discriminator,
};

use super::common::{
    ValueExpectation, checksum, checksum_parts, ensure_encode_budget, expected_discriminator,
    invalid, make_layer, payload_without_padding, protocol, resolve_u16, strict_or_diagnostic,
    truncated, typed_layer, validate_auto_raw_discriminator, validate_raw_child_discriminator,
};

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::Gre.as_str();

pub(crate) const GRE_BASE_LEN: usize = 4;
const GRE_OPTION_LEN: usize = 4;
const CHECKSUM_PRESENT: u16 = 0x8000;
const ROUTING_PRESENT: u16 = 0x4000;
const KEY_PRESENT: u16 = 0x2000;
const SEQUENCE_PRESENT: u16 = 0x1000;
const MUST_DISCARD_FLAGS: u16 = 0x0c00;
const IGNORED_RESERVED_FLAGS: u16 = 0x03f8;
const VERSION_MASK: u16 = 0x0007;

#[expect(
    clippy::arithmetic_side_effects,
    reason = "at most GRE_BASE_LEN plus three GRE_OPTION_LEN options, so the sum is 16 at the largest"
)]
fn gre_header_len(checksum: bool, key: bool, sequence: bool) -> usize {
    GRE_BASE_LEN
        + usize::from(checksum) * GRE_OPTION_LEN
        + usize::from(key) * GRE_OPTION_LEN
        + usize::from(sequence) * GRE_OPTION_LEN
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gre {
    pub protocol_type: WireValue<u16>,
    pub checksum: Option<WireValue<u16>>,
    pub key: Option<u32>,
    pub sequence: Option<u32>,
    pub reserved_bits: u8,
}

impl Default for Gre {
    fn default() -> Self {
        Self {
            protocol_type: WireValue::Auto,
            checksum: None,
            key: None,
            sequence: None,
            reserved_bits: 0,
        }
    }
}

reflective_layer! {
    fn gre_schema() => { protocol: protocol(NAME), name: "GRE" }
    impl Gre {
        "protocol_type" => { kind: Unsigned, derived: true, required: false, description: "Encapsulated EtherType discriminator", reflect: protocol_type, layout: (2, 4) },
        "checksum" => { kind: Unsigned, derived: true, required: false, description: "Optional checksum over the GRE header and payload", get |layer| layer.checksum.as_ref().map(reflect_get), set |layer, value, name| { let mut checksum = layer.checksum.clone().unwrap_or_default(); reflect_set(&mut checksum, gre_schema(), name, value)?; layer.checksum = Some(checksum); Ok(()) } },
        "key" => { kind: Unsigned, derived: false, required: false, description: "Optional GRE key", get |layer| layer.key.map(FieldValue::from), set |layer, value, name| { let mut key = layer.key.unwrap_or_default(); reflect_set(&mut key, gre_schema(), name, value)?; layer.key = Some(key); Ok(()) } },
        "sequence" => { kind: Unsigned, derived: false, required: false, description: "Optional GRE sequence number", get |layer| layer.sequence.map(FieldValue::from), set |layer, value, name| { let mut sequence = layer.sequence.unwrap_or_default(); reflect_set(&mut sequence, gre_schema(), name, value)?; layer.sequence = Some(sequence); Ok(()) } },
        "reserved_bits" => { kind: Unsigned, derived: false, required: false, description: "Receiver-ignored GRE bits 6 through 12", reflect: reserved_bits, layout: (0, 2) },
    }
    layout pub(crate) fn gre_static_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct GreCodec;

impl LayerCodec for GreCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &gre_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Gre>(NAME, layer)?;
        let header_len = gre_header_len(
            layer.checksum.is_some(),
            layer.key.is_some(),
            layer.sequence.is_some(),
        );
        ensure_encode_budget(NAME, header_len, context)?;
        let covered_payload = payload_without_padding(NAME, payload, context)?;

        let mut diagnostics = Vec::new();
        if layer.reserved_bits > 0x7f {
            return Err(invalid(NAME, "reserved bits exceed the 7-bit wire field"));
        }
        if layer.reserved_bits != 0 {
            strict_or_diagnostic(
                NAME,
                "build.gre_reserved_bits",
                "reserved_bits",
                "GRE bits 6 through 12 must be zero on transmission",
                context,
                &mut diagnostics,
            )?;
        }
        validate_auto_raw_discriminator(
            NAME,
            "protocol_type",
            &layer.protocol_type,
            context,
            &mut diagnostics,
        )?;
        let (protocol_type, materialized_protocol_type) = resolve_u16(
            NAME,
            "protocol_type",
            &layer.protocol_type,
            expected_discriminator(NAME, context, 0_u16, &layer.protocol_type),
            context.mode,
            &mut diagnostics,
        )?;
        validate_raw_child_discriminator(
            NAME,
            u64::from(protocol_type),
            context,
            &mut diagnostics,
        )?;

        let mut prefix = encode_prefix(layer, protocol_type, header_len);

        let materialized_checksum = if let Some(checksum_value) = &layer.checksum {
            let expected = checksum_parts(&[&prefix, covered_payload]);
            let (checksum, materialized) = resolve_u16(
                NAME,
                "checksum",
                checksum_value,
                ValueExpectation::Required(expected),
                context.mode,
                &mut diagnostics,
            )?;
            #[expect(
                clippy::indexing_slicing,
                reason = "layer.checksum is Some here, so encode_prefix reserved bytes 4..6 for the checksum"
            )]
            {
                prefix[4..6].copy_from_slice(&checksum.to_be_bytes());
            }
            Some(materialized)
        } else {
            None
        };

        let mut materialized = layer.clone();
        materialized.protocol_type = materialized_protocol_type;
        materialized.checksum = materialized_checksum;
        Ok(EncodedLayer::header(prefix, Box::new(materialized))
            .with_fields(gre_layout(layer))
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let Some(header) = input.first_chunk::<GRE_BASE_LEN>() else {
            return Err(truncated(NAME, GRE_BASE_LEN, input.len()));
        };
        let flags = u16::from_be_bytes([header[0], header[1]]);
        let version = flags & VERSION_MASK;
        if version != 0 {
            return Err(crate::codec::Error::Unsupported {
                protocol: protocol(NAME),
                message: format!("GRE version {version} is not supported"),
            });
        }
        if flags & ROUTING_PRESENT != 0 {
            return Err(crate::codec::Error::Unsupported {
                protocol: protocol(NAME),
                message: "GRE routing fields are not supported".to_owned(),
            });
        }
        if flags & MUST_DISCARD_FLAGS != 0 {
            return Err(crate::codec::Error::Unsupported {
                protocol: protocol(NAME),
                message: format!(
                    "must-discard GRE flags are non-zero (0x{:04x})",
                    flags & MUST_DISCARD_FLAGS
                ),
            });
        }

        let protocol_type = u16::from_be_bytes([header[2], header[3]]);
        let (header_len, checksum_value, key, sequence) = decode_options(input, flags)?;

        let mut diagnostics = Vec::new();
        let reserved_bits = ((flags & IGNORED_RESERVED_FLAGS) >> 3) as u8;
        if reserved_bits != 0 {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.gre_reserved_bits",
                    "receiver-ignored GRE bits 6 through 12 are non-zero",
                )
                .at_field("reserved_bits"),
            );
        }
        if checksum_value.is_some() && checksum(input) != 0 {
            diagnostics.push(
                Diagnostic::warning(GRE_CHECKSUM, "GRE checksum mismatch").at_field("checksum"),
            );
        }
        let layer = Gre {
            protocol_type: WireValue::Exact(protocol_type),
            checksum: checksum_value,
            key,
            sequence,
            reserved_bits,
        };
        let payload_len = input.len().saturating_sub(header_len);
        Ok(DecodedLayer {
            fields: gre_layout(&layer),
            layer: Box::new(layer),
            consumed: header_len,
            payload_len,
            next: vec![Discriminator(u64::from(protocol_type))],
            diagnostics,
            stop: payload_len == 0,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Gre::default(), fields)
    }
}

fn encode_prefix(layer: &Gre, protocol_type: u16, header_len: usize) -> Vec<u8> {
    let flags = if layer.checksum.is_some() {
        CHECKSUM_PRESENT
    } else {
        0
    } | if layer.key.is_some() { KEY_PRESENT } else { 0 }
        | if layer.sequence.is_some() {
            SEQUENCE_PRESENT
        } else {
            0
        }
        | (u16::from(layer.reserved_bits) << 3);
    let mut prefix = Vec::with_capacity(header_len);
    prefix.extend_from_slice(&flags.to_be_bytes());
    prefix.extend_from_slice(&protocol_type.to_be_bytes());
    if layer.checksum.is_some() {
        prefix.extend_from_slice(&[0; GRE_OPTION_LEN]);
    }
    if let Some(key) = layer.key {
        prefix.extend_from_slice(&key.to_be_bytes());
    }
    if let Some(sequence) = layer.sequence {
        prefix.extend_from_slice(&sequence.to_be_bytes());
    }
    prefix
}

type DecodedOptions = (usize, Option<WireValue<u16>>, Option<u32>, Option<u32>);

fn decode_options(input: &[u8], flags: u16) -> Result<DecodedOptions, crate::codec::Error> {
    let checksum_present = flags & CHECKSUM_PRESENT != 0;
    let key_present = flags & KEY_PRESENT != 0;
    let sequence_present = flags & SEQUENCE_PRESENT != 0;
    let header_len = gre_header_len(checksum_present, key_present, sequence_present);
    if input.len() < header_len {
        return Err(truncated(NAME, header_len, input.len()));
    }
    let mut cursor = GRE_BASE_LEN;
    let checksum_value = if checksum_present {
        let option = gre_option(input, cursor)?;
        let value = u16::from_be_bytes([option[0], option[1]]);
        if option[2] != 0 || option[3] != 0 {
            return Err(invalid(NAME, "reserved1 field is non-zero"));
        }
        cursor = cursor.saturating_add(GRE_OPTION_LEN);
        Some(WireValue::Exact(value))
    } else {
        None
    };
    let key = if key_present {
        let option = gre_option(input, cursor)?;
        cursor = cursor.saturating_add(GRE_OPTION_LEN);
        Some(u32::from_be_bytes(option))
    } else {
        None
    };
    let sequence = if sequence_present {
        Some(u32::from_be_bytes(gre_option(input, cursor)?))
    } else {
        None
    };
    Ok((header_len, checksum_value, key, sequence))
}

/// Reads the four-byte GRE option that starts at `cursor`.
fn gre_option(input: &[u8], cursor: usize) -> Result<[u8; GRE_OPTION_LEN], crate::codec::Error> {
    input
        .get(cursor..)
        .and_then(<[u8]>::first_chunk::<GRE_OPTION_LEN>)
        .copied()
        .ok_or_else(|| truncated(NAME, cursor.saturating_add(GRE_OPTION_LEN), input.len()))
}

fn gre_layout(layer: &Gre) -> Vec<crate::layout::FieldLayout> {
    // GRE optional fields are dynamic; only the fixed prefix is static.
    let mut fields = gre_static_layout();
    let mut cursor = GRE_BASE_LEN;
    if layer.checksum.is_some() {
        fields.push(gre_dynamic_field(
            "checksum",
            cursor,
            cursor.saturating_add(2),
        ));
        cursor = cursor.saturating_add(GRE_OPTION_LEN);
    }
    if layer.key.is_some() {
        fields.push(gre_dynamic_field(
            "key",
            cursor,
            cursor.saturating_add(GRE_OPTION_LEN),
        ));
        cursor = cursor.saturating_add(GRE_OPTION_LEN);
    }
    if layer.sequence.is_some() {
        fields.push(gre_dynamic_field(
            "sequence",
            cursor,
            cursor.saturating_add(GRE_OPTION_LEN),
        ));
    }
    fields
}

fn gre_dynamic_field(name: &'static str, start: usize, end: usize) -> crate::layout::FieldLayout {
    crate::layout::FieldLayout {
        name,
        range: crate::layout::ByteRange::new(start, end),
    }
}
