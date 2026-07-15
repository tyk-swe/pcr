#![no_main]

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use packetcraftr::packet::{
    build::{Builder, Context as BuildContext, Options as BuildOptions},
    document::{Format, Limits as DocumentLimits, Packet as PacketDocument},
    expression::{Options as ExpressionOptions, parse},
};
use packetcraftr::protocol::builtin::registry;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, input)) = data.split_first() else {
        return;
    };
    let input = &input[..input.len().min(64 * 1024)];
    let Ok(text) = std::str::from_utf8(input) else {
        return;
    };
    let registry = Arc::new(registry().unwrap());
    let packet = match mode % 3 {
        0 => parse(
            text,
            &registry,
            ExpressionOptions {
                max_layers: 64,
                max_bytes: 64 * 1024,
                ..ExpressionOptions::default()
            },
        )
        .ok(),
        1 => PacketDocument::parse_with_options(
            text,
            Format::Json,
            DocumentLimits {
                max_bytes: 64 * 1024,
                max_layers: 64,
                max_nesting: 16,
                max_fields_per_layer: 64,
                max_total_fields: 512,
                max_ast_nodes: 1024,
                max_collection_items: 64 * 1024,
                max_key_bytes: 128,
                max_owned_scalar_bytes: 64 * 1024,
            },
        )
            .ok()
            .and_then(|document| document.to_packet(&registry, 64).ok()),
        _ => PacketDocument::parse_with_options(
            text,
            Format::Yaml,
            DocumentLimits {
                max_bytes: 64 * 1024,
                max_layers: 64,
                max_nesting: 16,
                max_fields_per_layer: 64,
                max_total_fields: 512,
                max_ast_nodes: 1024,
                max_collection_items: 64 * 1024,
                max_key_bytes: 128,
                max_owned_scalar_bytes: 64 * 1024,
            },
        )
            .ok()
            .and_then(|document| document.to_packet(&registry, 64).ok()),
    };
    let Some(packet) = packet else { return };
    let Ok(built) = Builder::new(Arc::clone(&registry)).build(
        packet,
        BuildContext::default(),
        BuildOptions::default(),
    ) else {
        return;
    };
    assert!(built.bytes.len() <= 16 * 1024 * 1024);
    let document = PacketDocument::from_packet(&built.packet);
    let json = document.to_json_pretty().unwrap();
    let reparsed = PacketDocument::parse(&json, Format::Json, 16 * 1024 * 1024).unwrap();
    let packet = reparsed.to_packet(&registry, 64).unwrap();
    let rebuilt = Builder::new(registry)
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert_eq!(rebuilt.bytes, built.bytes);
});
