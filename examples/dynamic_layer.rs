// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr::packet::{
    Packet,
    document::PacketDocument,
    field::{FieldKind, FieldValue},
    layer::{DynamicLayer, FieldConstraints, FieldId, FieldSchema, Layer, LayerSchema, ProtocolId},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let schema = Arc::new(LayerSchema::new(
        ProtocolId::new("example.counter")?,
        "Example counter",
        ["counter"],
        1,
        [FieldSchema::new(
            FieldId::new("value")?,
            "value",
            ["v"],
            FieldKind::Unsigned,
            true,
            false,
            "Counter value",
            FieldConstraints::unsigned(0, 65_535),
        )?],
    )?);
    let layer = DynamicLayer::from_named(schema, [("v", FieldValue::Unsigned(7))])?;
    assert_eq!(
        layer.field_by_id(&FieldId::new("value")?),
        Some(FieldValue::Unsigned(7)),
    );

    let mut packet = Packet::new();
    packet.push(layer);
    println!("{}", PacketDocument::from_packet(&packet).to_json_pretty()?);
    Ok(())
}
