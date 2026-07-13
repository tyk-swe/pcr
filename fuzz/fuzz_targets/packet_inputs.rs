#![no_main]

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use packetcraftr::packet::{
    build::{Builder, Context as BuildContext, Options as BuildOptions},
    document::{Format, Packet as PacketDocument},
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
        1 => PacketDocument::parse(text, Format::Json, 64 * 1024)
            .ok()
            .and_then(|document| document.to_packet(&registry, 64).ok()),
        _ => PacketDocument::parse(text, Format::Yaml, 64 * 1024)
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
