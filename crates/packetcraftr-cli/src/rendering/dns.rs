// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fmt::Display;

use packetcraftr_core::{document::Packet, field};

use super::write_stdout_line;
use crate::errors::CliError;

pub(crate) fn render_dns_question(
    invocation: &crate::invocation::Invocation,
    name: impl Display,
    query_type: impl Display,
    class: impl Display,
) -> Result<(), CliError> {
    write_stdout_line(
        invocation,
        format_args!("  dns question: {name} type={query_type} class={class}"),
    )
}

pub(crate) fn render_dns_record(
    invocation: &crate::invocation::Invocation,
    section: impl Display,
    owner: impl Display,
    record_type: impl Display,
    class: impl Display,
    ttl: impl Display,
    data: impl Display,
) -> Result<(), CliError> {
    write_stdout_line(
        invocation,
        format_args!("  dns {section}: {owner} type={record_type} class={class} ttl={ttl} {data}"),
    )
}

pub(crate) fn render_dns_records(
    invocation: &crate::invocation::Invocation,
    packet: &Packet,
) -> Result<(), CliError> {
    for layer in &packet.layers {
        if layer.protocol.as_str() == "dns" {
            render_dns_fields(invocation, &layer.fields)?;
        }
    }
    Ok(())
}

pub(crate) fn render_dns_fields(
    invocation: &crate::invocation::Invocation,
    fields: &BTreeMap<String, field::Value>,
) -> Result<(), CliError> {
    if let Some(field::Value::List(questions)) = fields.get("questions") {
        for question in questions {
            let field::Value::Object(parts) = question else {
                continue;
            };
            if let (Some(name), Some(query_type), Some(class)) =
                (parts.get("name"), parts.get("type"), parts.get("class"))
            {
                render_dns_question(invocation, name, query_type, class)?;
            }
        }
    }
    for (field, section) in [
        ("answers", "answer"),
        ("authorities", "authority"),
        ("additionals", "additional"),
    ] {
        let Some(field::Value::List(records)) = fields.get(field) else {
            continue;
        };
        for record in records {
            let field::Value::Object(parts) = record else {
                continue;
            };
            if let (Some(owner), Some(type_code), Some(class), Some(ttl), Some(data)) = (
                parts.get("owner"),
                parts.get("type"),
                parts.get("class"),
                parts.get("ttl"),
                parts.get("value"),
            ) {
                render_dns_record(invocation, section, owner, type_code, class, ttl, data)?;
            }
        }
    }
    Ok(())
}
