// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::codec::{MAX_OPTION_BYTES, NAME, parse, serialize};
use super::model::{
    KIND_END, KIND_MSS, KIND_NOP, KIND_SACK, KIND_SACK_PERMITTED, KIND_TIMESTAMPS,
    KIND_WINDOW_SCALE,
};
use super::{SackBlock, Tcp, TcpOption};
use crate::{
    field::{FieldKind, FieldValue},
    layer::{FieldError, FieldSchema, Schema, reflective_layer},
    protocol::common::{
        out_of_range, protocol,
        structured::{Object, list, member, object},
        wrong_type,
    },
};

reflective_layer! {
    pub(super) fn tcp_schema() => { protocol: protocol(NAME), name: "TCP" }
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
        "options" => { kind: List, derived: false, required: false, description: "Ordered standard or unknown TCP options",
            children: OPTION_FIELDS,
            get |layer| Some(options_value(&layer.options)),
            set |layer, value, name| { layer.options = parse_field(value, tcp_schema(), name)?; Ok(()) },
            layout: (20, header_len) },
    }
    layout pub(super) fn tcp_layout(header_len: usize);
}

const SACK_EDGE_FIELDS: &[FieldSchema] = &[
    member("left_edge", FieldKind::Unsigned, &[]),
    member("right_edge", FieldKind::Unsigned, &[]),
];

const OPTION_FIELDS: &[FieldSchema] = &[
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

fn options_value(options: &[TcpOption]) -> FieldValue {
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
fn parse_field(
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
    use bytes::Bytes;

    use super::*;

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
            assert!(parse_field(options_value(&options), tcp_schema(), "options").is_err());
        }
        assert_eq!(serialize(&vec![TcpOption::Nop; 40]).unwrap(), vec![1; 40]);
        // A malformed zero-block SACK remains representable as raw wire data.
        let raw = parse(&Bytes::from_static(&[5, 2]));
        assert_eq!(serialize(&raw).unwrap(), [5, 2]);
    }
}
