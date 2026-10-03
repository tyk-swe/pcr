// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::decode;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::builtin;

#[test]
fn dissection_limits_reject_before_parsing() {
    let registry = builtin::registry();
    let frame = Frame::new(
        std::time::SystemTime::UNIX_EPOCH,
        LinkType::IPV4,
        vec![0_u8; 20],
    )
    .expect("frame must be valid");
    let error = decode::Dissector::new(registry)
        .decode(
            frame,
            decode::Options {
                limits: packetcraftr_core::packet::Limits {
                    max_packet_size: 19,
                    ..packetcraftr_core::packet::Limits::default()
                },
            },
        )
        .expect_err("oversized input must be rejected before codec traversal");
    assert!(error.to_string().contains("packet size"));
}
