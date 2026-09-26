// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use super::{Dhcpv6, Duid, Option6, Value6};
use crate::{
    field::{self, FieldKind, FieldValue},
    layer::{FieldSchema, reflect_set, reflective_layer},
    protocol::{
        BuiltinProtocol,
        common::{
            out_of_range, read_only,
            structured::{Object, list, member, object},
            wrong_type,
        },
    },
};
use bytes::Bytes;
use std::net::Ipv6Addr;

const DUID_FIELDS: &[FieldSchema] = &[
    member("type", FieldKind::Unsigned, &[]),
    member("data", FieldKind::Bytes, &[]),
    member("hardware_type", FieldKind::Unsigned, &[]),
    member("time", FieldKind::Unsigned, &[]),
    member("link_address", FieldKind::Bytes, &[]),
    member("enterprise", FieldKind::Unsigned, &[]),
    member("identifier", FieldKind::Bytes, &[]),
    member("uuid", FieldKind::Bytes, &[]),
];
fn duid_value(duid: &Duid) -> FieldValue {
    let mut fields = std::collections::BTreeMap::from([("type".to_owned(), duid.kind.into())]);
    let data = &duid.data;
    match (duid.kind, data.len()) {
        (1, n) if n > 6 => {
            fields.insert(
                "hardware_type".to_owned(),
                u16::from_be_bytes([data[0], data[1]]).into(),
            );
            fields.insert(
                "time".to_owned(),
                u32::from_be_bytes(data[2..6].try_into().expect("DUID time")).into(),
            );
            fields.insert("link_address".to_owned(), data.slice(6..).into());
        }
        (2, n) if n > 4 => {
            fields.insert(
                "enterprise".to_owned(),
                u32::from_be_bytes(data[..4].try_into().expect("enterprise number")).into(),
            );
            fields.insert("identifier".to_owned(), data.slice(4..).into());
        }
        (3, n) if n > 2 => {
            fields.insert(
                "hardware_type".to_owned(),
                u16::from_be_bytes([data[0], data[1]]).into(),
            );
            fields.insert("link_address".to_owned(), data.slice(2..).into());
        }
        (4, 16) => {
            fields.insert("uuid".to_owned(), data.clone().into());
        }
        _ => {
            fields.insert("data".to_owned(), data.clone().into());
        }
    }
    FieldValue::Object(fields)
}
fn parse_duid(value: FieldValue, field: &str) -> Result<Duid, field::Error> {
    let mut object = Object::new(value, schema(), field)?;
    let kind = object.required_value::<u16>("type")?;
    let duid = if object.contains("data") {
        Duid {
            kind,
            data: object.required_value("data")?,
        }
    } else {
        match kind {
            1 => Duid::link_layer_time(
                object.required_value("hardware_type")?,
                object.required_value("time")?,
                object.required_value::<Bytes>("link_address")?,
            )
            .map_err(|_| out_of_range(schema(), field))?,
            2 => Duid::enterprise(
                object.required_value("enterprise")?,
                object.required_value::<Bytes>("identifier")?,
            )
            .map_err(|_| out_of_range(schema(), field))?,
            3 => Duid::link_layer(
                object.required_value("hardware_type")?,
                object.required_value::<Bytes>("link_address")?,
            )
            .map_err(|_| out_of_range(schema(), field))?,
            4 => {
                let uuid = object.required_value::<Bytes>("uuid")?;
                Duid::uuid(
                    uuid.as_ref()
                        .try_into()
                        .map_err(|_| out_of_range(schema(), field))?,
                )
            }
            _ => return Err(wrong_type(schema(), field, "unknown DUID with data bytes")),
        }
    };
    object.finish()?;
    Ok(duid)
}
fn options_value(options: &[Option6]) -> FieldValue {
    FieldValue::List(
        options
            .iter()
            .map(|option| {
                object([
                    ("code", option.code.into()),
                    (
                        "value",
                        match &option.value {
                            Value6::Identifier(duid) => object([("duid", duid_value(duid))]),
                            Value6::Association {
                                iaid,
                                t1,
                                t2,
                                options,
                            } => object([
                                ("iaid", (*iaid).into()),
                                ("t1", (*t1).into()),
                                ("t2", (*t2).into()),
                                ("options", options_value(options)),
                            ]),
                            Value6::TemporaryAssociation { iaid, options } => object([
                                ("iaid", (*iaid).into()),
                                ("options", options_value(options)),
                            ]),
                            Value6::Address {
                                address,
                                preferred_lifetime,
                                valid_lifetime,
                                options,
                            } => object([
                                ("address", (*address).into()),
                                ("preferred_lifetime", (*preferred_lifetime).into()),
                                ("valid_lifetime", (*valid_lifetime).into()),
                                ("options", options_value(options)),
                            ]),
                            Value6::Prefix {
                                prefix,
                                prefix_length,
                                preferred_lifetime,
                                valid_lifetime,
                                options,
                            } => object([
                                ("prefix", (*prefix).into()),
                                ("prefix_length", (*prefix_length).into()),
                                ("preferred_lifetime", (*preferred_lifetime).into()),
                                ("valid_lifetime", (*valid_lifetime).into()),
                                ("options", options_value(options)),
                            ]),
                            Value6::Requested(codes) => object([(
                                "codes",
                                FieldValue::List(codes.iter().map(|code| (*code).into()).collect()),
                            )]),
                            Value6::Byte(value) => object([("number", (*value).into())]),
                            Value6::Number(value) => object([("number", (*value).into())]),
                            Value6::Seconds(value) => object([("seconds", (*value).into())]),
                            Value6::Relay(message) => object([("message", message_value(message))]),
                            Value6::Status { code, message } => object([
                                ("status", (*code).into()),
                                ("message_text", message.clone().into()),
                            ]),
                            Value6::Addresses(addresses) => object([(
                                "addresses",
                                FieldValue::List(
                                    addresses.iter().map(|address| (*address).into()).collect(),
                                ),
                            )]),
                            Value6::Flag => object([]),
                            Value6::Raw(data) => object([("data", data.clone().into())]),
                        },
                    ),
                ])
            })
            .collect(),
    )
}
fn message_value(message: &Dhcpv6) -> FieldValue {
    let mut fields = std::collections::BTreeMap::from([
        ("message_type".to_owned(), message.message_type.into()),
        ("options".to_owned(), options_value(&message.options)),
    ]);
    if message.is_relay() {
        fields.insert("hop_count".to_owned(), message.hop_count.into());
        fields.insert("link_address".to_owned(), message.link_address.into());
        fields.insert("peer_address".to_owned(), message.peer_address.into());
    } else {
        fields.insert("transaction_id".to_owned(), message.transaction_id.into());
    }
    FieldValue::Object(fields)
}
fn nested(
    value: &mut Object,
    field: &str,
    depth: usize,
    count: &mut usize,
) -> Result<Vec<Option6>, field::Error> {
    value
        .take("options")
        .map(|value| parse_options(value, field, depth + 1, count))
        .transpose()
        .map(Option::unwrap_or_default)
}
fn parse_message(
    value: FieldValue,
    field: &str,
    depth: usize,
    count: &mut usize,
) -> Result<Dhcpv6, field::Error> {
    if depth > 8 {
        return Err(out_of_range(schema(), field));
    }
    let mut value = Object::new(value, schema(), field)?;
    let mut message = Dhcpv6 {
        message_type: value.required_value("message_type")?,
        ..Default::default()
    };
    if message.is_relay() {
        message.hop_count = value.value("hop_count", 0)?;
        message.link_address = value.value("link_address", Ipv6Addr::UNSPECIFIED)?;
        message.peer_address = value.value("peer_address", Ipv6Addr::UNSPECIFIED)?;
    } else {
        message.transaction_id = value.value("transaction_id", 0)?;
    }
    message.options = value
        .take("options")
        .map(|value| parse_options(value, field, depth, count))
        .transpose()?
        .unwrap_or_default();
    value.finish()?;
    Ok(message)
}
fn parse_options(
    value: FieldValue,
    field: &str,
    depth: usize,
    count: &mut usize,
) -> Result<Vec<Option6>, field::Error> {
    let values = list(value, 4096, schema(), field)?;
    if depth > 8 && !values.is_empty() {
        return Err(out_of_range(schema(), field));
    }
    values
        .into_iter()
        .map(|value| {
            *count += 1;
            if *count > 4096 {
                return Err(out_of_range(schema(), field));
            }
            let mut option = Object::new(value, schema(), field)?;
            let code = option.required_value::<u16>("code")?;
            let mut value = Object::new(option.required("value")?, schema(), field)?;
            option.finish()?;
            let parsed = if value.contains("data") {
                Value6::Raw(value.required_value("data")?)
            } else {
                match code {
                    1 | 2 => Value6::Identifier(parse_duid(value.required("duid")?, field)?),
                    3 | 25 => Value6::Association {
                        iaid: value.required_value("iaid")?,
                        t1: value.value("t1", 0)?,
                        t2: value.value("t2", 0)?,
                        options: nested(&mut value, field, depth, count)?,
                    },
                    4 => Value6::TemporaryAssociation {
                        iaid: value.required_value("iaid")?,
                        options: nested(&mut value, field, depth, count)?,
                    },
                    5 => Value6::Address {
                        address: value.required_with("address", Ipv6Addr::UNSPECIFIED)?,
                        preferred_lifetime: value.required_value("preferred_lifetime")?,
                        valid_lifetime: value.required_value("valid_lifetime")?,
                        options: nested(&mut value, field, depth, count)?,
                    },
                    26 => Value6::Prefix {
                        prefix: value.required_with("prefix", Ipv6Addr::UNSPECIFIED)?,
                        prefix_length: value.required_value("prefix_length")?,
                        preferred_lifetime: value.required_value("preferred_lifetime")?,
                        valid_lifetime: value.required_value("valid_lifetime")?,
                        options: nested(&mut value, field, depth, count)?,
                    },
                    6 => Value6::Requested(
                        list(value.required("codes")?, 32767, schema(), field)?
                            .into_iter()
                            .map(|value| {
                                let mut code = 0u16;
                                reflect_set(&mut code, schema(), field, value)?;
                                Ok(code)
                            })
                            .collect::<Result<_, field::Error>>()?,
                    ),
                    7 | 19 => Value6::Byte(value.required_value("number")?),
                    8 => Value6::Number(value.required_value("number")?),
                    32 | 82 | 83 => Value6::Seconds(value.required_value("seconds")?),
                    9 => Value6::Relay(Box::new(parse_message(
                        value.required("message")?,
                        field,
                        depth + 1,
                        count,
                    )?)),
                    13 => Value6::Status {
                        code: value.required_value("status")?,
                        message: value.value("message_text", Bytes::new())?,
                    },
                    12 | 23 => Value6::Addresses(
                        list(value.required("addresses")?, 4095, schema(), field)?
                            .into_iter()
                            .map(|value| {
                                let mut address = Ipv6Addr::UNSPECIFIED;
                                reflect_set(&mut address, schema(), field, value)?;
                                Ok(address)
                            })
                            .collect::<Result<_, field::Error>>()?,
                    ),
                    14 | 20 => Value6::Flag,
                    _ => {
                        return Err(wrong_type(
                            schema(),
                            field,
                            "unknown option value with data bytes",
                        ));
                    }
                }
            };
            value.finish()?;
            Ok(Option6 {
                code,
                value: parsed,
            })
        })
        .collect()
}

const VALUE_0: &[FieldSchema] = &[
    member("duid", FieldKind::Object, DUID_FIELDS),
    member("iaid", FieldKind::Unsigned, &[]),
    member("t1", FieldKind::Unsigned, &[]),
    member("t2", FieldKind::Unsigned, &[]),
    member("address", FieldKind::Ipv6, &[]),
    member("prefix", FieldKind::Ipv6, &[]),
    member("prefix_length", FieldKind::Unsigned, &[]),
    member("preferred_lifetime", FieldKind::Unsigned, &[]),
    member("valid_lifetime", FieldKind::Unsigned, &[]),
    member("codes", FieldKind::List, &[]),
    member("number", FieldKind::Unsigned, &[]),
    member("seconds", FieldKind::Unsigned, &[]),
    member("status", FieldKind::Unsigned, &[]),
    member("message_text", FieldKind::Bytes, &[]),
    member("addresses", FieldKind::List, &[]),
    member("data", FieldKind::Bytes, &[]),
    member("options", FieldKind::List, &[]),
    member("message", FieldKind::Object, &[]),
];
const OPTIONS_0: &[FieldSchema] = &[
    member("code", FieldKind::Unsigned, &[]),
    member("value", FieldKind::Object, VALUE_0),
];
const MESSAGE_0: &[FieldSchema] = &[
    member("message_type", FieldKind::Unsigned, &[]),
    member("transaction_id", FieldKind::Unsigned, &[]),
    member("hop_count", FieldKind::Unsigned, &[]),
    member("link_address", FieldKind::Ipv6, &[]),
    member("peer_address", FieldKind::Ipv6, &[]),
    member("options", FieldKind::List, OPTIONS_0),
];

const VALUE_1: &[FieldSchema] = &[
    member("duid", FieldKind::Object, DUID_FIELDS),
    member("iaid", FieldKind::Unsigned, &[]),
    member("t1", FieldKind::Unsigned, &[]),
    member("t2", FieldKind::Unsigned, &[]),
    member("address", FieldKind::Ipv6, &[]),
    member("prefix", FieldKind::Ipv6, &[]),
    member("prefix_length", FieldKind::Unsigned, &[]),
    member("preferred_lifetime", FieldKind::Unsigned, &[]),
    member("valid_lifetime", FieldKind::Unsigned, &[]),
    member("codes", FieldKind::List, &[]),
    member("number", FieldKind::Unsigned, &[]),
    member("seconds", FieldKind::Unsigned, &[]),
    member("status", FieldKind::Unsigned, &[]),
    member("message_text", FieldKind::Bytes, &[]),
    member("addresses", FieldKind::List, &[]),
    member("data", FieldKind::Bytes, &[]),
    member("options", FieldKind::List, OPTIONS_0),
    member("message", FieldKind::Object, MESSAGE_0),
];
const OPTIONS_1: &[FieldSchema] = &[
    member("code", FieldKind::Unsigned, &[]),
    member("value", FieldKind::Object, VALUE_1),
];
const MESSAGE_1: &[FieldSchema] = &[
    member("message_type", FieldKind::Unsigned, &[]),
    member("transaction_id", FieldKind::Unsigned, &[]),
    member("hop_count", FieldKind::Unsigned, &[]),
    member("link_address", FieldKind::Ipv6, &[]),
    member("peer_address", FieldKind::Ipv6, &[]),
    member("options", FieldKind::List, OPTIONS_1),
];

const VALUE_2: &[FieldSchema] = &[
    member("duid", FieldKind::Object, DUID_FIELDS),
    member("iaid", FieldKind::Unsigned, &[]),
    member("t1", FieldKind::Unsigned, &[]),
    member("t2", FieldKind::Unsigned, &[]),
    member("address", FieldKind::Ipv6, &[]),
    member("prefix", FieldKind::Ipv6, &[]),
    member("prefix_length", FieldKind::Unsigned, &[]),
    member("preferred_lifetime", FieldKind::Unsigned, &[]),
    member("valid_lifetime", FieldKind::Unsigned, &[]),
    member("codes", FieldKind::List, &[]),
    member("number", FieldKind::Unsigned, &[]),
    member("seconds", FieldKind::Unsigned, &[]),
    member("status", FieldKind::Unsigned, &[]),
    member("message_text", FieldKind::Bytes, &[]),
    member("addresses", FieldKind::List, &[]),
    member("data", FieldKind::Bytes, &[]),
    member("options", FieldKind::List, OPTIONS_1),
    member("message", FieldKind::Object, MESSAGE_1),
];
const OPTIONS_2: &[FieldSchema] = &[
    member("code", FieldKind::Unsigned, &[]),
    member("value", FieldKind::Object, VALUE_2),
];
const MESSAGE_2: &[FieldSchema] = &[
    member("message_type", FieldKind::Unsigned, &[]),
    member("transaction_id", FieldKind::Unsigned, &[]),
    member("hop_count", FieldKind::Unsigned, &[]),
    member("link_address", FieldKind::Ipv6, &[]),
    member("peer_address", FieldKind::Ipv6, &[]),
    member("options", FieldKind::List, OPTIONS_2),
];

const VALUE_3: &[FieldSchema] = &[
    member("duid", FieldKind::Object, DUID_FIELDS),
    member("iaid", FieldKind::Unsigned, &[]),
    member("t1", FieldKind::Unsigned, &[]),
    member("t2", FieldKind::Unsigned, &[]),
    member("address", FieldKind::Ipv6, &[]),
    member("prefix", FieldKind::Ipv6, &[]),
    member("prefix_length", FieldKind::Unsigned, &[]),
    member("preferred_lifetime", FieldKind::Unsigned, &[]),
    member("valid_lifetime", FieldKind::Unsigned, &[]),
    member("codes", FieldKind::List, &[]),
    member("number", FieldKind::Unsigned, &[]),
    member("seconds", FieldKind::Unsigned, &[]),
    member("status", FieldKind::Unsigned, &[]),
    member("message_text", FieldKind::Bytes, &[]),
    member("addresses", FieldKind::List, &[]),
    member("data", FieldKind::Bytes, &[]),
    member("options", FieldKind::List, OPTIONS_2),
    member("message", FieldKind::Object, MESSAGE_2),
];
const OPTIONS_3: &[FieldSchema] = &[
    member("code", FieldKind::Unsigned, &[]),
    member("value", FieldKind::Object, VALUE_3),
];
const MESSAGE_3: &[FieldSchema] = &[
    member("message_type", FieldKind::Unsigned, &[]),
    member("transaction_id", FieldKind::Unsigned, &[]),
    member("hop_count", FieldKind::Unsigned, &[]),
    member("link_address", FieldKind::Ipv6, &[]),
    member("peer_address", FieldKind::Ipv6, &[]),
    member("options", FieldKind::List, OPTIONS_3),
];

const VALUE_4: &[FieldSchema] = &[
    member("duid", FieldKind::Object, DUID_FIELDS),
    member("iaid", FieldKind::Unsigned, &[]),
    member("t1", FieldKind::Unsigned, &[]),
    member("t2", FieldKind::Unsigned, &[]),
    member("address", FieldKind::Ipv6, &[]),
    member("prefix", FieldKind::Ipv6, &[]),
    member("prefix_length", FieldKind::Unsigned, &[]),
    member("preferred_lifetime", FieldKind::Unsigned, &[]),
    member("valid_lifetime", FieldKind::Unsigned, &[]),
    member("codes", FieldKind::List, &[]),
    member("number", FieldKind::Unsigned, &[]),
    member("seconds", FieldKind::Unsigned, &[]),
    member("status", FieldKind::Unsigned, &[]),
    member("message_text", FieldKind::Bytes, &[]),
    member("addresses", FieldKind::List, &[]),
    member("data", FieldKind::Bytes, &[]),
    member("options", FieldKind::List, OPTIONS_3),
    member("message", FieldKind::Object, MESSAGE_3),
];
const OPTIONS_4: &[FieldSchema] = &[
    member("code", FieldKind::Unsigned, &[]),
    member("value", FieldKind::Object, VALUE_4),
];
const MESSAGE_4: &[FieldSchema] = &[
    member("message_type", FieldKind::Unsigned, &[]),
    member("transaction_id", FieldKind::Unsigned, &[]),
    member("hop_count", FieldKind::Unsigned, &[]),
    member("link_address", FieldKind::Ipv6, &[]),
    member("peer_address", FieldKind::Ipv6, &[]),
    member("options", FieldKind::List, OPTIONS_4),
];

const VALUE_5: &[FieldSchema] = &[
    member("duid", FieldKind::Object, DUID_FIELDS),
    member("iaid", FieldKind::Unsigned, &[]),
    member("t1", FieldKind::Unsigned, &[]),
    member("t2", FieldKind::Unsigned, &[]),
    member("address", FieldKind::Ipv6, &[]),
    member("prefix", FieldKind::Ipv6, &[]),
    member("prefix_length", FieldKind::Unsigned, &[]),
    member("preferred_lifetime", FieldKind::Unsigned, &[]),
    member("valid_lifetime", FieldKind::Unsigned, &[]),
    member("codes", FieldKind::List, &[]),
    member("number", FieldKind::Unsigned, &[]),
    member("seconds", FieldKind::Unsigned, &[]),
    member("status", FieldKind::Unsigned, &[]),
    member("message_text", FieldKind::Bytes, &[]),
    member("addresses", FieldKind::List, &[]),
    member("data", FieldKind::Bytes, &[]),
    member("options", FieldKind::List, OPTIONS_4),
    member("message", FieldKind::Object, MESSAGE_4),
];
const OPTIONS_5: &[FieldSchema] = &[
    member("code", FieldKind::Unsigned, &[]),
    member("value", FieldKind::Object, VALUE_5),
];
const MESSAGE_5: &[FieldSchema] = &[
    member("message_type", FieldKind::Unsigned, &[]),
    member("transaction_id", FieldKind::Unsigned, &[]),
    member("hop_count", FieldKind::Unsigned, &[]),
    member("link_address", FieldKind::Ipv6, &[]),
    member("peer_address", FieldKind::Ipv6, &[]),
    member("options", FieldKind::List, OPTIONS_5),
];

const VALUE_6: &[FieldSchema] = &[
    member("duid", FieldKind::Object, DUID_FIELDS),
    member("iaid", FieldKind::Unsigned, &[]),
    member("t1", FieldKind::Unsigned, &[]),
    member("t2", FieldKind::Unsigned, &[]),
    member("address", FieldKind::Ipv6, &[]),
    member("prefix", FieldKind::Ipv6, &[]),
    member("prefix_length", FieldKind::Unsigned, &[]),
    member("preferred_lifetime", FieldKind::Unsigned, &[]),
    member("valid_lifetime", FieldKind::Unsigned, &[]),
    member("codes", FieldKind::List, &[]),
    member("number", FieldKind::Unsigned, &[]),
    member("seconds", FieldKind::Unsigned, &[]),
    member("status", FieldKind::Unsigned, &[]),
    member("message_text", FieldKind::Bytes, &[]),
    member("addresses", FieldKind::List, &[]),
    member("data", FieldKind::Bytes, &[]),
    member("options", FieldKind::List, OPTIONS_5),
    member("message", FieldKind::Object, MESSAGE_5),
];
const OPTIONS_6: &[FieldSchema] = &[
    member("code", FieldKind::Unsigned, &[]),
    member("value", FieldKind::Object, VALUE_6),
];
const MESSAGE_6: &[FieldSchema] = &[
    member("message_type", FieldKind::Unsigned, &[]),
    member("transaction_id", FieldKind::Unsigned, &[]),
    member("hop_count", FieldKind::Unsigned, &[]),
    member("link_address", FieldKind::Ipv6, &[]),
    member("peer_address", FieldKind::Ipv6, &[]),
    member("options", FieldKind::List, OPTIONS_6),
];

const VALUE_7: &[FieldSchema] = &[
    member("duid", FieldKind::Object, DUID_FIELDS),
    member("iaid", FieldKind::Unsigned, &[]),
    member("t1", FieldKind::Unsigned, &[]),
    member("t2", FieldKind::Unsigned, &[]),
    member("address", FieldKind::Ipv6, &[]),
    member("prefix", FieldKind::Ipv6, &[]),
    member("prefix_length", FieldKind::Unsigned, &[]),
    member("preferred_lifetime", FieldKind::Unsigned, &[]),
    member("valid_lifetime", FieldKind::Unsigned, &[]),
    member("codes", FieldKind::List, &[]),
    member("number", FieldKind::Unsigned, &[]),
    member("seconds", FieldKind::Unsigned, &[]),
    member("status", FieldKind::Unsigned, &[]),
    member("message_text", FieldKind::Bytes, &[]),
    member("addresses", FieldKind::List, &[]),
    member("data", FieldKind::Bytes, &[]),
    member("options", FieldKind::List, OPTIONS_6),
    member("message", FieldKind::Object, MESSAGE_6),
];
const OPTIONS_7: &[FieldSchema] = &[
    member("code", FieldKind::Unsigned, &[]),
    member("value", FieldKind::Object, VALUE_7),
];
const MESSAGE_7: &[FieldSchema] = &[
    member("message_type", FieldKind::Unsigned, &[]),
    member("transaction_id", FieldKind::Unsigned, &[]),
    member("hop_count", FieldKind::Unsigned, &[]),
    member("link_address", FieldKind::Ipv6, &[]),
    member("peer_address", FieldKind::Ipv6, &[]),
    member("options", FieldKind::List, OPTIONS_7),
];

const VALUE_8: &[FieldSchema] = &[
    member("duid", FieldKind::Object, DUID_FIELDS),
    member("iaid", FieldKind::Unsigned, &[]),
    member("t1", FieldKind::Unsigned, &[]),
    member("t2", FieldKind::Unsigned, &[]),
    member("address", FieldKind::Ipv6, &[]),
    member("prefix", FieldKind::Ipv6, &[]),
    member("prefix_length", FieldKind::Unsigned, &[]),
    member("preferred_lifetime", FieldKind::Unsigned, &[]),
    member("valid_lifetime", FieldKind::Unsigned, &[]),
    member("codes", FieldKind::List, &[]),
    member("number", FieldKind::Unsigned, &[]),
    member("seconds", FieldKind::Unsigned, &[]),
    member("status", FieldKind::Unsigned, &[]),
    member("message_text", FieldKind::Bytes, &[]),
    member("addresses", FieldKind::List, &[]),
    member("data", FieldKind::Bytes, &[]),
    member("options", FieldKind::List, OPTIONS_7),
    member("message", FieldKind::Object, MESSAGE_7),
];
const OPTIONS_8: &[FieldSchema] = &[
    member("code", FieldKind::Unsigned, &[]),
    member("value", FieldKind::Object, VALUE_8),
];

reflective_layer! {
    pub(super) fn schema() => {protocol:crate::layer::Id::new(BuiltinProtocol::Dhcpv6.as_str()),name:"DHCPv6"}
    impl Dhcpv6 {
        "message_type" => {kind:Unsigned,derived:false,required:false,description:"DHCPv6 message type",reflect:message_type,layout:(0,1)},
        "transaction_id" | "xid" => {kind:Unsigned,derived:false,required:false,description:"24-bit identity in ordinary messages",get |layer| (!layer.is_relay()).then(||layer.transaction_id.into()),set |layer,value,name| reflect_set(&mut layer.transaction_id,schema(),name,value)},
        "hop_count" => {kind:Unsigned,derived:false,required:false,description:"Relay hop count",get |layer| layer.is_relay().then(||layer.hop_count.into()),set |layer,value,name| reflect_set(&mut layer.hop_count,schema(),name,value)},
        "link_address" => {kind:Ipv6,derived:false,required:false,description:"Relay link address",get |layer| layer.is_relay().then(||layer.link_address.into()),set |layer,value,name| reflect_set(&mut layer.link_address,schema(),name,value)},
        "peer_address" => {kind:Ipv6,derived:false,required:false,description:"Relay peer address",get |layer| layer.is_relay().then(||layer.peer_address.into()),set |layer,value,name| reflect_set(&mut layer.peer_address,schema(),name,value)},
        "options" => {kind:List,derived:false,required:false,description:"Ordered nested DHCP options",children:OPTIONS_8,get |layer| Some(options_value(&layer.options)),set |layer,value,name| {layer.options=parse_options(value,name,0,&mut 0)?;Ok(())}},
        "wire" => {kind:Bytes,derived:false,required:false,description:"Retained complete DHCP wire",get |layer| (!layer.wire.is_empty()).then(||layer.wire.clone().into()),set |_layer,_value,name| read_only(schema(),name)}
    }
    layout pub(super) fn layout();
}
