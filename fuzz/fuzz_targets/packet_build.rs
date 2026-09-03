#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use packetcraftr_core::Packet;
use packetcraftr_core::build::{Builder, Context, Options as BuildOptions};
use packetcraftr_core::codec::Mode;
use packetcraftr_core::decode::{Dissector, Options as DecodeOptions};
use packetcraftr_core::document::{DocumentLimits, Format, Packet as DocPacket};
use packetcraftr_core::expression::{self, Options as ExprOptions};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::registry::Registry;
use std::sync::Arc;
use std::time::SystemTime;

const MAX_LAYERS: usize = 16;
const MAX_PACKET_SIZE: usize = 64 * 1024;

// Every encoder runs behind the expression and document parsers, so a packet
// that either one accepts must encode without panicking in both modes, stay
// within the packet size ceiling, and decode again from its own bytes.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let registry = builtin::registry();

    let expr_options = ExprOptions {
        max_bytes: 64 * 1024,
        max_layers: MAX_LAYERS,
        max_nesting: 16,
    };
    if let Ok(packet) = expression::parse(text, &registry, expr_options) {
        build_both_modes(&registry, &packet);
    }

    let document_limits = DocumentLimits {
        max_input_bytes: 64 * 1024,
        max_layers: MAX_LAYERS,
        ..DocumentLimits::DEFAULT
    };
    if let Ok(document) = DocPacket::parse_with_limits(text, Format::Json, &document_limits)
        && let Ok(packet) = document.to_packet(&registry, MAX_LAYERS)
    {
        build_both_modes(&registry, &packet);
    }
});

fn build_both_modes(registry: &Arc<Registry>, packet: &Packet) {
    let builder = Builder::new(Arc::clone(registry));
    for mode in [Mode::Strict, Mode::Permissive] {
        let options = BuildOptions {
            mode,
            max_layers: MAX_LAYERS,
            max_packet_size: MAX_PACKET_SIZE,
        };
        let Ok(built) = builder.build(packet.clone(), Context::default(), options) else {
            continue;
        };
        assert!(
            built.bytes.len() <= MAX_PACKET_SIZE,
            "built packet exceeds the size ceiling it was built under"
        );

        // A successfully built packet must decode from its own bytes on the
        // link type the builder chose for it; the root layer decides.
        let root = built.packet.iter().next().map(|layer| layer.schema().name);
        let link_type = match root {
            Some("ethernet") => LinkType::ETHERNET,
            Some("ipv4") => LinkType::IPV4,
            Some("ipv6") => LinkType::IPV6,
            _ => return,
        };
        let dissector = Dissector::new(Arc::clone(registry));
        if let Ok(frame) = Frame::new(SystemTime::now(), link_type, Bytes::clone(&built.bytes)) {
            let decode_options = DecodeOptions {
                max_layers: MAX_LAYERS,
                max_packet_size: MAX_PACKET_SIZE,
            };
            assert!(
                dissector.decode(frame, decode_options).is_ok(),
                "built {mode:?} packet failed to decode from its own bytes"
            );
        }
    }
}
