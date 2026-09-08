// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Stable typed tuples for the existing recursive list reflection contract.

use super::{Record, RecordValue};
use crate::field::FieldValue;

pub(super) fn records(records: &[Record]) -> FieldValue {
    FieldValue::List(
        records
            .iter()
            .map(|record| {
                FieldValue::List(vec![
                    record.owner.to_string().into(),
                    record.value.type_code().into(),
                    record.class.into(),
                    record.ttl.into(),
                    value(&record.value),
                ])
            })
            .collect(),
    )
}

fn value(record: &RecordValue) -> FieldValue {
    let values = match record {
        RecordValue::A(address) => vec!["a".into(), (*address).into()],
        RecordValue::Aaaa(address) => vec!["aaaa".into(), (*address).into()],
        RecordValue::Cname(name) => vec!["cname".into(), name.to_string().into()],
        RecordValue::Ns(name) => vec!["ns".into(), name.to_string().into()],
        RecordValue::Ptr(name) => vec!["ptr".into(), name.to_string().into()],
        RecordValue::Mx {
            preference,
            exchange,
        } => vec![
            "mx".into(),
            (*preference).into(),
            exchange.to_string().into(),
        ],
        RecordValue::Soa {
            primary_name_server,
            responsible_mailbox,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => vec![
            "soa".into(),
            primary_name_server.to_string().into(),
            responsible_mailbox.to_string().into(),
            (*serial).into(),
            (*refresh).into(),
            (*retry).into(),
            (*expire).into(),
            (*minimum).into(),
        ],
        RecordValue::Srv {
            priority,
            weight,
            port,
            target,
        } => vec![
            "srv".into(),
            (*priority).into(),
            (*weight).into(),
            (*port).into(),
            target.to_string().into(),
        ],
        RecordValue::Caa { flags, tag, value } => vec![
            "caa".into(),
            (*flags).into(),
            tag.clone().into(),
            value.clone().into(),
        ],
        RecordValue::Txt(strings) => vec![
            "txt".into(),
            FieldValue::List(strings.iter().cloned().map(Into::into).collect()),
        ],
        RecordValue::Unknown { rdata, .. } => vec!["unknown".into(), rdata.clone().into()],
        RecordValue::Opt(edns) => vec![
            "opt".into(),
            edns.udp_payload_size.into(),
            edns.extended_response_code.into(),
            edns.version.into(),
            edns.dnssec_ok.into(),
            edns.flags.into(),
            FieldValue::List(
                edns.options
                    .iter()
                    .map(|option| {
                        FieldValue::List(vec![option.code.into(), option.data.clone().into()])
                    })
                    .collect(),
            ),
        ],
    };
    FieldValue::List(values)
}
