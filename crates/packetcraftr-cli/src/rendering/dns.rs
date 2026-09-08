// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS record details shared by offline text commands.

use packetcraftr_core::{document::Packet, field::FieldValue};

use super::write_plain_line;
use crate::errors::CliError;

pub(crate) fn render_dns_records(packet: &Packet) -> Result<(), CliError> {
    for layer in &packet.layers {
        if layer.protocol.as_str() != "dns" {
            continue;
        }
        for (field, section) in [
            ("answers", "answer"),
            ("authorities", "authority"),
            ("additionals", "additional"),
        ] {
            let Some(FieldValue::List(records)) = layer.fields.get(field) else {
                continue;
            };
            for record in records {
                let FieldValue::List(parts) = record else {
                    continue;
                };
                let [owner, type_code, class, ttl, data] = parts.as_slice() else {
                    continue;
                };
                write_plain_line(format_args!(
                    "  dns {section}: {owner} type={type_code} class={class} ttl={ttl} {data}"
                ))?;
            }
        }
    }
    Ok(())
}
