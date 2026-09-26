// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS text: one line shape for a question and one for a resource record,
//! whichever command printed them and whichever model they came from.

use std::collections::BTreeMap;
use std::fmt::Display;

use packetcraftr_core::{document::Packet, field::FieldValue};

use super::write_stdout_line;
use crate::errors::CliError;

/// One question: `  dns question: <name> type=<type> class=<class>`.
pub(crate) fn render_dns_question(
    name: impl Display,
    query_type: impl Display,
    class: impl Display,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "  dns question: {name} type={query_type} class={class}"
    ))
}

/// One resource record:
/// `  dns <section>: <owner> type=<type> class=<class> ttl=<ttl> <data>`.
pub(crate) fn render_dns_record(
    section: impl Display,
    owner: impl Display,
    record_type: impl Display,
    class: impl Display,
    ttl: impl Display,
    data: impl Display,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "  dns {section}: {owner} type={record_type} class={class} ttl={ttl} {data}"
    ))
}

/// The questions and records of every DNS layer in a decoded packet.
pub(crate) fn render_dns_records(packet: &Packet) -> Result<(), CliError> {
    for layer in &packet.layers {
        if layer.protocol.as_str() == "dns" {
            render_dns_fields(&layer.fields)?;
        }
    }
    Ok(())
}

/// The questions and records one DNS message's reflected fields carry.
fn render_dns_fields(fields: &BTreeMap<String, FieldValue>) -> Result<(), CliError> {
    if let Some(FieldValue::List(questions)) = fields.get("questions") {
        for question in questions {
            let FieldValue::Object(parts) = question else {
                continue;
            };
            if let (Some(name), Some(query_type), Some(class)) =
                (parts.get("name"), parts.get("type"), parts.get("class"))
            {
                render_dns_question(name, query_type, class)?;
            }
        }
    }
    for (field, section) in [
        ("answers", "answer"),
        ("authorities", "authority"),
        ("additionals", "additional"),
    ] {
        let Some(FieldValue::List(records)) = fields.get(field) else {
            continue;
        };
        for record in records {
            let FieldValue::Object(parts) = record else {
                continue;
            };
            if let (Some(owner), Some(type_code), Some(class), Some(ttl), Some(data)) = (
                parts.get("owner"),
                parts.get("type"),
                parts.get("class"),
                parts.get("ttl"),
                parts.get("value"),
            ) {
                render_dns_record(section, owner, type_code, class, ttl, data)?;
            }
        }
    }
    Ok(())
}
