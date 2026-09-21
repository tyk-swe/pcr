// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Dns, Edns, EdnsOption, Name, Question, Record, RecordValue, dns_schema};
use crate::field::{FieldKind, FieldValue};
use crate::layer::{FieldError, FieldSchema, reflect_set};
use crate::protocol::common::structured::{Object, list, member, object};
use crate::protocol::common::{out_of_range, wrong_type};
use bytes::Bytes;

pub(super) const QUESTION_FIELDS: &[FieldSchema] = &[
    member("name", FieldKind::Text, &[]),
    member("type", FieldKind::Unsigned, &[]),
    member("class", FieldKind::Unsigned, &[]),
];
const OPTION_FIELDS: &[FieldSchema] = &[
    member("code", FieldKind::Unsigned, &[]),
    member("data", FieldKind::Bytes, &[]),
];
const VALUE_FIELDS: &[FieldSchema] = &[
    member("kind", FieldKind::Text, &[]),
    member("type", FieldKind::Unsigned, &[]),
    member("address", FieldKind::Ipv4, &[]),
    member("address6", FieldKind::Ipv6, &[]),
    member("name", FieldKind::Text, &[]),
    member("preference", FieldKind::Unsigned, &[]),
    member("exchange", FieldKind::Text, &[]),
    member("primary_name_server", FieldKind::Text, &[]),
    member("responsible_mailbox", FieldKind::Text, &[]),
    member("serial", FieldKind::Unsigned, &[]),
    member("refresh", FieldKind::Unsigned, &[]),
    member("retry", FieldKind::Unsigned, &[]),
    member("expire", FieldKind::Unsigned, &[]),
    member("minimum", FieldKind::Unsigned, &[]),
    member("priority", FieldKind::Unsigned, &[]),
    member("weight", FieldKind::Unsigned, &[]),
    member("port", FieldKind::Unsigned, &[]),
    member("target", FieldKind::Text, &[]),
    member("flags", FieldKind::Unsigned, &[]),
    member("tag", FieldKind::Bytes, &[]),
    member("data", FieldKind::Bytes, &[]),
    member("strings", FieldKind::List, &[]),
    member("rdata", FieldKind::Bytes, &[]),
    member("udp_payload_size", FieldKind::Unsigned, &[]),
    member("extended_response_code", FieldKind::Unsigned, &[]),
    member("version", FieldKind::Unsigned, &[]),
    member("dnssec_ok", FieldKind::Bool, &[]),
    member("options", FieldKind::List, OPTION_FIELDS),
];
pub(super) const RECORD_FIELDS: &[FieldSchema] = &[
    member("owner", FieldKind::Text, &[]),
    member("type", FieldKind::Unsigned, &[]),
    member("class", FieldKind::Unsigned, &[]),
    member("ttl", FieldKind::Unsigned, &[]),
    member("value", FieldKind::Object, VALUE_FIELDS),
];

pub(super) fn questions(values: &[Question]) -> FieldValue {
    FieldValue::List(
        values
            .iter()
            .map(|q| {
                object([
                    ("name", q.name.to_string().into()),
                    ("type", q.query_type.into()),
                    ("class", q.class.into()),
                ])
            })
            .collect(),
    )
}

pub(super) fn records(values: &[Record]) -> FieldValue {
    FieldValue::List(
        values
            .iter()
            .map(|record| {
                object([
                    ("owner", record.owner.to_string().into()),
                    ("type", record.value.type_code().into()),
                    ("class", record.class.into()),
                    ("ttl", record.ttl.into()),
                    ("value", record_value(&record.value)),
                ])
            })
            .collect(),
    )
}

fn record_value(value: &RecordValue) -> FieldValue {
    match value {
        RecordValue::A(v) => object([("kind", "a".into()), ("address", (*v).into())]),
        RecordValue::Aaaa(v) => object([("kind", "aaaa".into()), ("address6", (*v).into())]),
        RecordValue::Cname(v) | RecordValue::Ns(v) | RecordValue::Ptr(v) => object([
            (
                "kind",
                match value {
                    RecordValue::Cname(_) => "cname",
                    RecordValue::Ns(_) => "ns",
                    _ => "ptr",
                }
                .into(),
            ),
            ("name", v.to_string().into()),
        ]),
        RecordValue::Mx {
            preference,
            exchange,
        } => object([
            ("kind", "mx".into()),
            ("preference", (*preference).into()),
            ("exchange", exchange.to_string().into()),
        ]),
        RecordValue::Soa {
            primary_name_server,
            responsible_mailbox,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => object([
            ("kind", "soa".into()),
            (
                "primary_name_server",
                primary_name_server.to_string().into(),
            ),
            (
                "responsible_mailbox",
                responsible_mailbox.to_string().into(),
            ),
            ("serial", (*serial).into()),
            ("refresh", (*refresh).into()),
            ("retry", (*retry).into()),
            ("expire", (*expire).into()),
            ("minimum", (*minimum).into()),
        ]),
        RecordValue::Srv {
            priority,
            weight,
            port,
            target,
        } => object([
            ("kind", "srv".into()),
            ("priority", (*priority).into()),
            ("weight", (*weight).into()),
            ("port", (*port).into()),
            ("target", target.to_string().into()),
        ]),
        RecordValue::Caa { flags, tag, value } => object([
            ("kind", "caa".into()),
            ("flags", (*flags).into()),
            ("tag", tag.clone().into()),
            ("data", value.clone().into()),
        ]),
        RecordValue::Txt(strings) => object([
            ("kind", "txt".into()),
            (
                "strings",
                FieldValue::List(strings.iter().cloned().map(Into::into).collect()),
            ),
        ]),
        RecordValue::Unknown { type_code, rdata } => object([
            ("kind", "unknown".into()),
            ("type", (*type_code).into()),
            ("rdata", rdata.clone().into()),
        ]),
        RecordValue::Opt(edns) => object([
            ("kind", "opt".into()),
            ("udp_payload_size", edns.udp_payload_size.into()),
            ("extended_response_code", edns.extended_response_code.into()),
            ("version", edns.version.into()),
            ("dnssec_ok", edns.dnssec_ok.into()),
            ("flags", edns.flags.into()),
            (
                "options",
                FieldValue::List(
                    edns.options
                        .iter()
                        .map(|opt| {
                            object([("code", opt.code.into()), ("data", opt.data.clone().into())])
                        })
                        .collect(),
                ),
            ),
        ]),
    }
}

fn name(object: &mut Object, key: &str) -> Result<Name, FieldError> {
    let FieldValue::Text(text) = object.required(key)? else {
        return Err(wrong_type(dns_schema(), key, "DNS name text"));
    };
    text.parse().map_err(|_| out_of_range(dns_schema(), key))
}

fn record(value: FieldValue, field: &str) -> Result<Record, FieldError> {
    let mut o = Object::new(value, dns_schema(), field)?;
    let owner = name(&mut o, "owner")?;
    let value = parse_value(o.required("value")?, field)?;
    let (default_class, default_ttl) = match &value {
        RecordValue::Opt(edns) => (edns.udp_payload_size, edns.record_ttl()),
        _ => (1, 0),
    };
    let class = o.value("class", default_class)?;
    let ttl = o.value("ttl", default_ttl)?;
    if matches!(value, RecordValue::Opt(_)) && (class != default_class || ttl != default_ttl) {
        return Err(out_of_range(dns_schema(), field));
    }
    if o.value("type", value.type_code())? != value.type_code() {
        return Err(out_of_range(dns_schema(), field));
    }
    o.finish()?;
    Ok(Record {
        owner,
        class,
        ttl,
        value,
    })
}

fn parse_value(value: FieldValue, field: &str) -> Result<RecordValue, FieldError> {
    let mut o = Object::new(value, dns_schema(), field)?;
    let kind = o.value("kind", String::new())?;
    let value = match kind.as_str() {
        "a" => RecordValue::A(o.value("address", std::net::Ipv4Addr::UNSPECIFIED)?),
        "aaaa" => RecordValue::Aaaa(o.value("address6", std::net::Ipv6Addr::UNSPECIFIED)?),
        "cname" => RecordValue::Cname(name(&mut o, "name")?),
        "ns" => RecordValue::Ns(name(&mut o, "name")?),
        "ptr" => RecordValue::Ptr(name(&mut o, "name")?),
        "mx" => RecordValue::Mx {
            preference: o.value("preference", 0u16)?,
            exchange: name(&mut o, "exchange")?,
        },
        "soa" => RecordValue::Soa {
            primary_name_server: name(&mut o, "primary_name_server")?,
            responsible_mailbox: name(&mut o, "responsible_mailbox")?,
            serial: o.value("serial", 0u32)?,
            refresh: o.value("refresh", 0u32)?,
            retry: o.value("retry", 0u32)?,
            expire: o.value("expire", 0u32)?,
            minimum: o.value("minimum", 0u32)?,
        },
        "srv" => RecordValue::Srv {
            priority: o.value("priority", 0u16)?,
            weight: o.value("weight", 0u16)?,
            port: o.value("port", 0u16)?,
            target: name(&mut o, "target")?,
        },
        "caa" => RecordValue::Caa {
            flags: o.value("flags", 0u8)?,
            tag: o.value("tag", Bytes::new())?,
            value: o.value("data", Bytes::new())?,
        },
        "txt" => {
            let mut strings = Vec::new();
            for value in list(o.required("strings")?, 4096, dns_schema(), field)? {
                let mut bytes = Bytes::new();
                reflect_set(&mut bytes, dns_schema(), field, value)?;
                if bytes.len() > 255 {
                    return Err(out_of_range(dns_schema(), field));
                }
                strings.push(bytes);
            }
            RecordValue::Txt(strings)
        }
        "unknown" => RecordValue::Unknown {
            type_code: o.value("type", 0u16)?,
            rdata: o.value("rdata", Bytes::new())?,
        },
        "opt" => {
            let explicit_flags = o.contains("flags");
            let mut flags = o.value("flags", 0u16)?;
            let dnssec_ok = o.value("dnssec_ok", flags & 0x8000 != 0)?;
            if explicit_flags && (flags & 0x8000 != 0) != dnssec_ok {
                return Err(out_of_range(dns_schema(), "dnssec_ok"));
            }
            flags = (flags & !0x8000) | (u16::from(dnssec_ok) << 15);
            let mut options = Vec::new();
            if let Some(value) = o.take("options") {
                for value in list(value, 4096, dns_schema(), field)? {
                    let mut option = Object::new(value, dns_schema(), field)?;
                    options.push(EdnsOption {
                        code: option.value("code", 0u16)?,
                        data: option.value("data", Bytes::new())?,
                    });
                    option.finish()?;
                }
            }
            RecordValue::Opt(Edns {
                udp_payload_size: o.value("udp_payload_size", 1232u16)?,
                extended_response_code: o.value("extended_response_code", 0u8)?,
                version: o.value("version", 0u8)?,
                dnssec_ok,
                flags,
                options,
            })
        }
        _ => {
            return Err(wrong_type(
                dns_schema(),
                field,
                "a supported DNS record kind or unknown",
            ));
        }
    };
    o.finish()?;
    Ok(value)
}

pub(super) fn assign(layer: &mut Dns, field: &str, value: FieldValue) -> Result<(), FieldError> {
    macro_rules! scalar { ($($name:ident),* $(,)?) => { match field {
        $(stringify!($name) => return reflect_set(&mut layer.$name, dns_schema(), field, value),)*
        _ => {}
    } }; }
    scalar!(
        id,
        response,
        opcode,
        authoritative_answer,
        truncated,
        recursion_desired,
        recursion_available,
        reserved,
        authenticated_data,
        checking_disabled,
        rcode,
        question_count,
        answer_count,
        authority_count,
        additional_count
    );
    match field {
        "questions" => {
            let mut questions = Vec::new();
            for value in list(value, 64, dns_schema(), field)? {
                let mut q = Object::new(value, dns_schema(), field)?;
                questions.push(Question {
                    name: name(&mut q, "name")?,
                    query_type: q.value("type", 1u16)?,
                    class: q.value("class", 1u16)?,
                });
                q.finish()?;
            }
            layer.questions = questions;
        }
        "answers" | "authorities" | "additionals" => {
            let records = list(value, 4096, dns_schema(), field)?
                .into_iter()
                .map(|value| record(value, field))
                .collect::<Result<Vec<_>, _>>()?;
            match field {
                "answers" => layer.answers = records,
                "authorities" => layer.authorities = records,
                _ => layer.additionals = records,
            }
        }
        _ => {
            return Err(FieldError::UnknownField {
                protocol: dns_schema().protocol,
                field: field.to_owned(),
            });
        }
    }
    Ok(())
}
