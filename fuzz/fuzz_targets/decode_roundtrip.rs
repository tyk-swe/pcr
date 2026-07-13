#![no_main]

use std::sync::Arc;
use std::time::SystemTime;

use libfuzzer_sys::fuzz_target;
use packetcraftr::capture::{Frame, LinkType};
use packetcraftr::packet::{
    build::{Builder, Context as BuildContext, Mode as BuildMode, Options as BuildOptions},
    decode::{Decoder, Options as DecodeOptions},
};
use packetcraftr::protocol::builtin::registry;

const ROOTS: [LinkType; 10] = [
    LinkType::NULL,
    LinkType::ETHERNET,
    LinkType::BSD_RAW,
    LinkType::RAW,
    LinkType::LOOP,
    LinkType::LINUX_SLL,
    LinkType::IPV4,
    LinkType::IPV6,
    LinkType::LINUX_SLL2,
    LinkType(147),
];

fuzz_target!(|data: &[u8]| {
    let Some((&selector, bytes)) = data.split_first() else {
        return;
    };
    let bytes = bytes[..bytes.len().min(64 * 1024)].to_vec();
    let registry = Arc::new(registry().unwrap());
    let decoded = Decoder::new(Arc::clone(&registry))
        .decode(
            Frame::new(
                SystemTime::UNIX_EPOCH,
                ROOTS[selector as usize % ROOTS.len()],
                bytes.clone(),
            )
            .unwrap(),
            DecodeOptions {
                max_layers: 64,
                max_packet_size: 64 * 1024,
                verify_checksums: true,
            },
        )
        .unwrap();
    assert_eq!(decoded.layout.layers.len(), decoded.packet.len());
    for (index, layer) in decoded.layout.layers.iter().enumerate() {
        assert_eq!(layer.index, index);
        assert!(layer.range.start <= layer.range.end && layer.range.end <= bytes.len());
        assert!(layer
            .fields
            .iter()
            .all(|field| field.range.start >= layer.range.start
                && field.range.end <= layer.range.end));
    }
    if !bytes.is_empty() {
        let rebuilt = Builder::new(registry)
            .build(
                decoded.packet,
                BuildContext::default(),
                BuildOptions {
                    mode: BuildMode::Permissive,
                    max_layers: 64,
                    max_packet_size: 64 * 1024,
                },
            )
            .unwrap();
        assert_eq!(rebuilt.bytes.as_ref(), bytes.as_slice());
    }
});
