// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::Diagnostic,
    field::FieldValue,
    layer::{Layer, reflective_layer},
};

use crate::protocol::common::{
    ensure_encode_budget, invalid, make_layer, protocol, strict_or_diagnostic, truncated,
    typed_layer,
};

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::Lldp.as_str();

const TLV_HEADER_LEN: usize = 2;
const TLV_END: u8 = 0;
const TLV_CHASSIS_ID: u8 = 1;
const TLV_TTL: u8 = 3;
/// Chassis ID, Port ID, and Time To Live must open every LLDPDU.
const MANDATORY_TLVS: u8 = 3;
const TTL_VALUE_LEN: usize = 2;

/// LLDP data unit (IEEE 802.1AB): the verbatim TLV chain, then whatever
/// follows its End of LLDPDU TLV.
///
/// `tlvs` holds the chain exactly as received, including the End TLV when
/// present; unknown and organizationally specific TLVs are never interpreted.
/// Any structural problem is reported through diagnostics instead of
/// rejecting the bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lldp {
    pub tlvs: Bytes,
    /// Bytes after the End TLV, such as minimum-frame padding.
    pub trailing: Bytes,
}

impl Default for Lldp {
    /// A minimal valid LLDPDU: a locally administered MAC chassis ID, a
    /// locally assigned port ID `1`, a 120 s TTL, and the End TLV.
    fn default() -> Self {
        Self {
            tlvs: Bytes::from_static(&[
                0x02, 0x07, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // chassis ID
                0x04, 0x02, 0x07, b'1', // port ID
                0x06, 0x02, 0x00, 0x78, // TTL
                0x00, 0x00, // end of LLDPDU
            ]),
            trailing: Bytes::new(),
        }
    }
}

reflective_layer! {
    fn lldp_schema() => { protocol: protocol(NAME), name: "LLDP" }
    impl Lldp {
        "tlvs" => { kind: Bytes, derived: false, required: true, description: "Verbatim TLV chain including the End of LLDPDU TLV when present", reflect: tlvs, layout: (0, tlvs_end) },
        "trailing" => { kind: Bytes, derived: false, required: false, description: "Bytes after the End of LLDPDU TLV", reflect: trailing, layout: (tlvs_end, trailing_end) },
    }
    layout pub(crate) fn lldp_layout(tlvs_end: usize, trailing_end: usize);
}

impl Lldp {
    /// Yields `(type, value)` for each TLV before the End of LLDPDU TLV, and
    /// stops at the first TLV that does not fit in `tlvs`.
    pub fn tlv_iter(&self) -> impl Iterator<Item = (u8, &[u8])> + '_ {
        let mut cursor = 0_usize;
        std::iter::from_fn(move || {
            let (kind, value, next) = read_tlv(&self.tlvs, cursor)?;
            if kind == TLV_END && value.is_empty() {
                return None;
            }
            cursor = next;
            Some((kind, value))
        })
    }
}

/// Reads the TLV at `cursor`, returning its type, value, and the offset after
/// it, or `None` when the header or value does not fit.
fn read_tlv(chain: &[u8], cursor: usize) -> Option<(u8, &[u8], usize)> {
    let header = chain
        .get(cursor..)
        .and_then(<[u8]>::first_chunk::<TLV_HEADER_LEN>)?;
    let kind = header[0] >> 1;
    let length = (usize::from(header[0] & 1) << 8) | usize::from(header[1]);
    let value_start = cursor.checked_add(TLV_HEADER_LEN)?;
    let value_end = value_start.checked_add(length)?;
    let value = chain.get(value_start..value_end)?;
    Some((kind, value, value_end))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Problem {
    MandatoryOrder,
    TruncatedTlv,
    MissingEnd,
    ShortTtl,
    /// Only a built chain can carry bytes after its End TLV; a decoded chain
    /// ends there.
    EndNotLast,
}

impl Problem {
    fn decode_code(self) -> &'static str {
        match self {
            Self::MandatoryOrder => "decode.lldp_mandatory_order",
            Self::TruncatedTlv => "decode.lldp_truncated_tlv",
            Self::MissingEnd => "decode.lldp_missing_end",
            Self::ShortTtl => "decode.lldp_short_ttl",
            Self::EndNotLast => "decode.lldp_end_not_last",
        }
    }

    fn build_code(self) -> &'static str {
        match self {
            Self::MandatoryOrder => "build.lldp_mandatory_order",
            Self::TruncatedTlv => "build.lldp_truncated_tlv",
            Self::MissingEnd => "build.lldp_missing_end",
            Self::ShortTtl => "build.lldp_short_ttl",
            Self::EndNotLast => "build.lldp_end_not_last",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::MandatoryOrder => {
                "an LLDPDU must open with the Chassis ID, Port ID, and Time To Live TLVs in that order"
            }
            Self::TruncatedTlv => "an LLDP TLV header or value runs past the end of the data",
            Self::MissingEnd => "the LLDP TLV chain ends without an End of LLDPDU TLV",
            Self::ShortTtl => "the Time To Live TLV must carry a 2-byte value",
            Self::EndNotLast => {
                "bytes follow the End of LLDPDU TLV inside the TLV chain; they belong in trailing"
            }
        }
    }
}

struct Scan {
    /// Offset just past the End TLV, when the chain has one.
    end: Option<usize>,
    problems: Vec<Problem>,
}

/// Walks the chain with bounds-checked reads and never looks past `chain`.
fn scan(chain: &[u8]) -> Scan {
    let mut problems = Vec::new();
    let mut note = |problem: Problem| {
        if !problems.contains(&problem) {
            problems.push(problem);
        }
    };
    let mut cursor = 0_usize;
    let mut position = 0_u8;
    let mut end = None;
    loop {
        if cursor == chain.len() {
            if position < MANDATORY_TLVS {
                note(Problem::MandatoryOrder);
            }
            note(Problem::MissingEnd);
            break;
        }
        let Some((kind, value, next)) = read_tlv(chain, cursor) else {
            note(Problem::TruncatedTlv);
            break;
        };
        if kind == TLV_END && value.is_empty() {
            if position < MANDATORY_TLVS {
                note(Problem::MandatoryOrder);
            }
            end = Some(next);
            break;
        }
        if position < MANDATORY_TLVS {
            if kind != TLV_CHASSIS_ID.saturating_add(position) {
                note(Problem::MandatoryOrder);
            } else if kind == TLV_TTL && value.len() != TTL_VALUE_LEN {
                note(Problem::ShortTtl);
            }
            position = position.saturating_add(1);
        }
        cursor = next;
    }
    Scan { end, problems }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LldpCodec;

impl LayerCodec for LldpCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &lldp_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Lldp>(NAME, layer)?;
        let tlvs_end = layer.tlvs.len();
        let total = tlvs_end
            .checked_add(layer.trailing.len())
            .ok_or_else(|| invalid(NAME, "LLDP length overflow"))?;
        ensure_encode_budget(NAME, total, context)?;

        let mut diagnostics = Vec::new();
        let scanned = scan(&layer.tlvs);
        for problem in scanned.problems {
            strict_or_diagnostic(
                NAME,
                problem.build_code(),
                "tlvs",
                problem.message(),
                context,
                &mut diagnostics,
            )?;
        }
        if scanned.end.is_some_and(|end| end < tlvs_end) {
            strict_or_diagnostic(
                NAME,
                Problem::EndNotLast.build_code(),
                "tlvs",
                Problem::EndNotLast.message(),
                context,
                &mut diagnostics,
            )?;
        }

        let mut prefix = Vec::with_capacity(total);
        prefix.extend_from_slice(&layer.tlvs);
        prefix.extend_from_slice(&layer.trailing);
        Ok(EncodedLayer::header(prefix, Box::new(layer.clone()))
            .with_fields(lldp_layout(tlvs_end, total))
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        if input.is_empty() {
            return Err(truncated(NAME, TLV_HEADER_LEN, 0));
        }
        let scanned = scan(&input);
        let tlvs_end = scanned.end.unwrap_or(input.len());
        let layer = Lldp {
            tlvs: input.slice(..tlvs_end),
            trailing: input.slice(tlvs_end..),
        };
        let diagnostics = scanned
            .problems
            .into_iter()
            .map(|problem| {
                Diagnostic::warning(problem.decode_code(), problem.message()).at_field("tlvs")
            })
            .collect();
        let consumed = input.len();
        Ok(DecodedLayer {
            fields: lldp_layout(tlvs_end, consumed),
            layer: Box::new(layer),
            consumed,
            payload_len: 0,
            next: Vec::new(),
            diagnostics,
            stop: true,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Lldp::default(), fields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;

    fn encode(layer: &Lldp, mode: crate::codec::Mode) -> Result<EncodedLayer, crate::codec::Error> {
        let registry = crate::protocol::builtin::registry();
        let packet = Packet::new();
        let build_context = crate::codec::Context::default();
        let context = LayerEncodeContext {
            packet: &packet,
            index: 0,
            build_context: &build_context,
            mode,
            registry: &registry,
            child: None,
            remaining_packet_bytes: usize::MAX,
        };
        LldpCodec.encode(layer, &[], &context)
    }

    fn decode(input: &[u8]) -> Result<DecodedLayer, crate::codec::Error> {
        let registry = crate::protocol::builtin::registry();
        let context = LayerDecodeContext {
            parent: None,
            registry: &registry,
            network: None,
            discriminator: None,
        };
        LldpCodec.decode(Bytes::copy_from_slice(input), &context)
    }

    fn decoded_codes(input: &[u8]) -> Vec<&'static str> {
        decode(input)
            .unwrap()
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect()
    }

    const CHASSIS: [u8; 9] = [0x02, 0x07, 0x04, 0x02, 0, 0, 0, 0, 1];
    const PORT: [u8; 4] = [0x04, 0x02, 0x07, b'1'];
    const TTL: [u8; 4] = [0x06, 0x02, 0x00, 0x78];
    const END: [u8; 2] = [0, 0];

    fn chain(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    #[test]
    fn the_default_chain_is_valid_and_round_trips() {
        let layer = Lldp::default();
        assert_eq!(layer.tlv_iter().count(), 3);
        let encoded = encode(&layer, crate::codec::Mode::Strict).unwrap();
        assert!(encoded.diagnostics.is_empty());
        let decoded = decode(&encoded.prefix).unwrap();
        assert!(decoded.diagnostics.is_empty());
        assert_eq!(decoded.layer.downcast_ref::<Lldp>(), Some(&layer));
    }

    #[test]
    fn bytes_after_the_end_tlv_become_trailing_and_every_tlv_stays_verbatim() {
        let org_specific = [0xfe, 0x06, 0x12, 0x34, 0x56, 0x01, 0xaa, 0xbb];
        let name = [0x0a, 0x02, b'a', b'b'];
        let input = chain(&[
            &CHASSIS,
            &PORT,
            &TTL,
            &name,
            &org_specific,
            &END,
            &[0xff; 5],
        ]);
        let decoded = decode(&input).unwrap();
        assert!(decoded.diagnostics.is_empty());
        let layer = decoded.layer.downcast_ref::<Lldp>().unwrap();
        assert_eq!(layer.trailing.as_ref(), &[0xff; 5]);
        assert_eq!(layer.tlvs.len(), input.len() - 5);
        assert_eq!(
            layer.tlv_iter().last(),
            Some((127, [0x12, 0x34, 0x56, 0x01, 0xaa, 0xbb].as_slice()))
        );
        assert_eq!(
            encode(layer, crate::codec::Mode::Strict).unwrap().prefix,
            input
        );
    }

    #[test]
    fn the_nine_bit_length_reaches_past_255_and_overruns_are_reported() {
        // type 6 (system description) declaring 0x1ff value bytes
        let mut input = chain(&[&CHASSIS, &PORT, &TTL]);
        input.extend_from_slice(&[0x0d, 0xff, 1, 2, 3]);
        assert_eq!(decoded_codes(&input), ["decode.lldp_truncated_tlv"]);
        let decoded = decode(&input).unwrap();
        let layer = decoded.layer.downcast_ref::<Lldp>().unwrap();
        assert_eq!(layer.tlvs.len(), input.len());
        assert_eq!(layer.tlv_iter().count(), 3);

        let mut fits = chain(&[&CHASSIS, &PORT, &TTL]);
        fits.extend_from_slice(&[0x0d, 0xff]);
        fits.extend_from_slice(&[0x55; 0x1ff]);
        fits.extend_from_slice(&END);
        assert!(decoded_codes(&fits).is_empty());
    }

    #[test]
    fn ordering_end_and_ttl_problems_each_have_their_own_code() {
        let swapped = chain(&[&PORT, &CHASSIS, &TTL, &END]);
        assert_eq!(decoded_codes(&swapped), ["decode.lldp_mandatory_order"]);

        let early_end = chain(&[&CHASSIS, &END]);
        assert_eq!(decoded_codes(&early_end), ["decode.lldp_mandatory_order"]);

        let no_end = chain(&[&CHASSIS, &PORT, &TTL]);
        assert_eq!(decoded_codes(&no_end), ["decode.lldp_missing_end"]);

        let empty_tlv = [0x00, 0x00];
        assert_eq!(
            decoded_codes(&empty_tlv),
            ["decode.lldp_mandatory_order"],
            "an immediate End TLV leaves the mandatory TLVs absent"
        );

        let short_ttl = chain(&[&CHASSIS, &PORT, &[0x06, 0x01, 0x78], &END]);
        assert_eq!(decoded_codes(&short_ttl), ["decode.lldp_short_ttl"]);

        let long_ttl = chain(&[&CHASSIS, &PORT, &[0x06, 0x03, 0x00, 0x78, 0x00], &END]);
        assert_eq!(decoded_codes(&long_ttl), ["decode.lldp_short_ttl"]);
        let layer = Lldp {
            tlvs: Bytes::from(long_ttl),
            trailing: Bytes::new(),
        };
        assert!(encode(&layer, crate::codec::Mode::Strict).is_err());
        assert!(encode(&layer, crate::codec::Mode::Permissive).is_ok());

        let one_byte = chain(&[&CHASSIS, &PORT, &TTL, &[0x0a]]);
        assert_eq!(decoded_codes(&one_byte), ["decode.lldp_truncated_tlv"]);
    }

    #[test]
    fn strict_builds_refuse_what_permissive_builds_preserve() {
        let layer = Lldp {
            tlvs: Bytes::from(chain(&[&PORT, &CHASSIS, &TTL])),
            trailing: Bytes::from_static(b"x"),
        };
        let encoded = encode(&layer, crate::codec::Mode::Permissive).unwrap();
        assert_eq!(
            encoded.prefix.len(),
            layer.tlvs.len() + layer.trailing.len()
        );
        let codes: Vec<_> = encoded
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect();
        assert_eq!(
            codes,
            ["build.lldp_mandatory_order", "build.lldp_missing_end"]
        );
        assert!(encode(&layer, crate::codec::Mode::Strict).is_err());

        let end_inside = Lldp {
            tlvs: Bytes::from(chain(&[&CHASSIS, &PORT, &TTL, &END, &[1, 2]])),
            trailing: Bytes::new(),
        };
        assert!(encode(&end_inside, crate::codec::Mode::Strict).is_err());
        let permissive = encode(&end_inside, crate::codec::Mode::Permissive).unwrap();
        assert_eq!(permissive.diagnostics.len(), 1);
    }

    #[test]
    fn empty_input_is_truncated() {
        assert!(matches!(
            decode(&[]),
            Err(crate::codec::Error::Truncated { .. })
        ));
    }
}
