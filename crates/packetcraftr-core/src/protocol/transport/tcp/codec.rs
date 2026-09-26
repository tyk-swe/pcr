// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Standard TCP options typed over the option area.
//!
//! End-of-list and no-op markers, MSS, window scale, SACK-permitted/SACK, and
//! timestamps decode into variants; every other kind and every nonstandard
//! length stays byte-exact as [`TcpOption::Raw`]. A tail that cannot be a TLV
//! at all — a missing length byte, a length below two, or a length that runs
//! past the option area — becomes [`TcpOption::Trailing`] so decode never
//! loses wire bytes and re-encoding reproduces them exactly. EOL terminates
//! parsing; any remaining padding is preserved as `Trailing` too.

use bytes::Bytes;

use crate::{
    codec,
    field::{FieldKind, FieldValue},
    layer::{FieldError, FieldSchema, Schema},
    protocol::common::{
        invalid, out_of_range,
        structured::{Object, list, member, object},
        wrong_type,
    },
};

/// The option area the four-bit TCP data offset can address.
const MAX_OPTION_BYTES: usize = 40;

const KIND_END: u8 = 0;
const KIND_NOP: u8 = 1;
const KIND_MSS: u8 = 2;
const KIND_WINDOW_SCALE: u8 = 3;
const KIND_SACK_PERMITTED: u8 = 4;
const KIND_SACK: u8 = 5;
const KIND_TIMESTAMPS: u8 = 8;

/// One SACK block's inclusive sequence edge pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SackBlock {
    pub left_edge: u32,
    pub right_edge: u32,
}

/// A parsed TCP option, preserving declaration order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TcpOption {
    /// End of option list (kind 0, a single byte).
    End,
    /// No-operation padding (kind 1, a single byte).
    Nop,
    /// Maximum segment size (kind 2, length 4).
    Mss(u16),
    /// Window scale shift count (kind 3, length 3).
    WindowScale(u8),
    /// SACK-permitted marker (kind 4, length 2).
    SackPermitted,
    /// Selective acknowledgment blocks (kind 5, length 2 + 8n).
    Sack(Vec<SackBlock>),
    /// Timestamps option (kind 8, length 10): TSval and TSecr.
    Timestamps { value: u32, echo_reply: u32 },
    /// Any other kind, or a standard kind with a nonstandard length;
    /// `data` is the option body after the kind and length bytes.
    Raw { kind: u8, data: Bytes },
    /// Padding after EOL, or bytes that cannot decode as a TLV; always last.
    Trailing(Bytes),
}

impl TcpOption {
    /// Wire kind byte; `Trailing` has none.
    pub fn kind(&self) -> Option<u8> {
        Some(match self {
            Self::End => KIND_END,
            Self::Nop => KIND_NOP,
            Self::Mss(_) => KIND_MSS,
            Self::WindowScale(_) => KIND_WINDOW_SCALE,
            Self::SackPermitted => KIND_SACK_PERMITTED,
            Self::Sack(_) => KIND_SACK,
            Self::Timestamps { .. } => KIND_TIMESTAMPS,
            Self::Raw { kind, .. } => *kind,
            Self::Trailing(_) => return None,
        })
    }

    fn serialize(&self, output: &mut Vec<u8>) -> Result<(), codec::Error> {
        let invalid = |message: &str| invalid(super::NAME, message);
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
pub(super) fn serialize(options: &[TcpOption]) -> Result<Vec<u8>, codec::Error> {
    let invalid = |message: &str| invalid(super::NAME, message);
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

const SACK_EDGE_FIELDS: &[FieldSchema] = &[
    member("left_edge", FieldKind::Unsigned, &[]),
    member("right_edge", FieldKind::Unsigned, &[]),
];

pub(crate) const OPTION_FIELDS: &[FieldSchema] = &[
    member("kind", FieldKind::Unsigned, &[]),
    member("mss", FieldKind::Unsigned, &[]),
    member("window_scale", FieldKind::Unsigned, &[]),
    member("sack", FieldKind::List, SACK_EDGE_FIELDS),
    member("tsval", FieldKind::Unsigned, &[]),
    member("tsecr", FieldKind::Unsigned, &[]),
    member("data", FieldKind::Bytes, &[]),
    member("trailing", FieldKind::Bytes, &[]),
];

fn option_value(option: &TcpOption) -> FieldValue {
    let mut fields = Vec::with_capacity(3);
    if let Some(kind) = option.kind() {
        fields.push(("kind", FieldValue::Unsigned(u64::from(kind))));
    }
    match option {
        TcpOption::Mss(value) => fields.push(("mss", (*value).into())),
        TcpOption::WindowScale(shift) => fields.push(("window_scale", (*shift).into())),
        TcpOption::Sack(blocks) => fields.push((
            "sack",
            FieldValue::List(
                blocks
                    .iter()
                    .map(|block| {
                        object([
                            ("left_edge", block.left_edge.into()),
                            ("right_edge", block.right_edge.into()),
                        ])
                    })
                    .collect(),
            ),
        )),
        TcpOption::Timestamps { value, echo_reply } => {
            fields.push(("tsval", (*value).into()));
            fields.push(("tsecr", (*echo_reply).into()));
        }
        TcpOption::Raw { data, .. } => fields.push(("data", data.clone().into())),
        TcpOption::Trailing(bytes) => fields.push(("trailing", bytes.clone().into())),
        TcpOption::End | TcpOption::Nop | TcpOption::SackPermitted => {}
    }
    FieldValue::Object(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

pub(crate) fn options_value(options: &[TcpOption]) -> FieldValue {
    FieldValue::List(options.iter().map(option_value).collect())
}

fn sack_blocks(
    value: FieldValue,
    schema: &'static Schema,
    field: &str,
) -> Result<Vec<SackBlock>, FieldError> {
    list(value, 31, schema, field)?
        .into_iter()
        .map(|value| {
            let mut block = Object::new(value, schema, field)?;
            let parsed = SackBlock {
                left_edge: block.required_value("left_edge")?,
                right_edge: block.required_value("right_edge")?,
            };
            block.finish()?;
            Ok(parsed)
        })
        .collect()
}

/// Parses a constructed `options` field value: either verbatim bytes, which
/// are parsed like the wire form, or a list of typed option objects.
pub(crate) fn parse_field(
    value: FieldValue,
    schema: &'static Schema,
    field: &str,
) -> Result<Vec<TcpOption>, FieldError> {
    if let FieldValue::Bytes(bytes) = value {
        // Decoded input is bounded by the data offset, but a constructed value
        // carries no header, so bound it here rather than allocating an entry
        // per byte and only rejecting the size at encode time.
        if bytes.len() > MAX_OPTION_BYTES {
            return Err(out_of_range(schema, field));
        }
        return Ok(parse(&bytes));
    }
    let values = list(value, 64, schema, field)?;
    let mut options = Vec::with_capacity(values.len());
    for value in values {
        options.push(parse_option(value, schema, field)?);
    }
    serialize(&options).map_err(|_| out_of_range(schema, field))?;
    Ok(options)
}

fn parse_option(
    value: FieldValue,
    schema: &'static Schema,
    field: &str,
) -> Result<TcpOption, FieldError> {
    let mut option = Object::new(value, schema, field)?;
    if let Some(trailing) = option.take("trailing") {
        let bytes = match trailing {
            FieldValue::Bytes(bytes) => bytes,
            _ => return Err(wrong_type(schema, field, "trailing bytes")),
        };
        option.finish()?;
        return Ok(TcpOption::Trailing(bytes));
    }
    let kind: u8 = option.required_value("kind")?;
    let data = match option.take("data") {
        Some(FieldValue::Bytes(bytes)) => Some(bytes),
        Some(_) => return Err(wrong_type(schema, field, "option data bytes")),
        None => None,
    };
    // `option_value` writes `data` for `Raw` alone, so its presence decides the
    // variant ahead of the typed arms: a standard kind whose wire length was
    // nonstandard decodes to `Raw` and has to round-trip back to `Raw`.
    let parsed = match (kind, data) {
        (KIND_END, None) => TcpOption::End,
        (KIND_NOP, None) => TcpOption::Nop,
        (KIND_MSS, None) => TcpOption::Mss(option.required_value("mss")?),
        (KIND_WINDOW_SCALE, None) => TcpOption::WindowScale(option.required_value("window_scale")?),
        (KIND_SACK_PERMITTED, None) => TcpOption::SackPermitted,
        (KIND_SACK, None) => TcpOption::Sack(sack_blocks(option.required("sack")?, schema, field)?),
        (KIND_TIMESTAMPS, None) => TcpOption::Timestamps {
            value: option.required_value("tsval")?,
            echo_reply: option.required_value("tsecr")?,
        },
        (kind, data) => TcpOption::Raw {
            kind,
            data: data.unwrap_or_default(),
        },
    };
    option.finish()?;
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn constructed_options_enforce_the_wire_limit_before_encoding() {
        for options in [
            vec![TcpOption::Trailing(Bytes::from(vec![0; 65_536]))],
            vec![TcpOption::Nop; 41],
            vec![TcpOption::Sack(Vec::new())],
            vec![TcpOption::Sack(vec![
                SackBlock {
                    left_edge: 1,
                    right_edge: 2,
                };
                5
            ])],
        ] {
            assert!(serialize(&options).is_err());
            assert!(
                parse_field(
                    options_value(&options),
                    super::super::tcp_schema(),
                    "options"
                )
                .is_err()
            );
        }
        assert_eq!(wire(&vec![TcpOption::Nop; 40]), vec![1; 40]);
        // A malformed zero-block SACK remains representable as raw wire data.
        let raw = parse(&Bytes::from_static(&[5, 2]));
        assert_eq!(wire(&raw), [5, 2]);
    }
}
