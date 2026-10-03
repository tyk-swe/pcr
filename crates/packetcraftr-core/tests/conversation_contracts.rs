// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use std::net::Ipv4Addr;

use bytes::Bytes;
use packetcraftr_core::conversation::{Conversation, Error, MAX_FRAMES, Options as Spec, Protocol};
use packetcraftr_core::error::Classified;
use packetcraftr_core::layer::Raw;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::{Tcp, Udp};

const CLIENT_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const SERVER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);

fn recipe(transport: impl packetcraftr_core::layer::Layer, request: &[u8]) -> Packet {
    let mut packet = Packet::new();
    packet.push(Ethernet {
        source: CLIENT_MAC,
        destination: SERVER_MAC,
        ..Ethernet::default()
    });
    packet.push(Ipv4 {
        source: CLIENT_IP,
        destination: SERVER_IP,
        ..Ipv4::default()
    });
    packet.push(transport);
    if !request.is_empty() {
        packet.push(Raw::new(request.to_vec()));
    }
    packet
}

fn tcp_recipe(request: &[u8]) -> Packet {
    recipe(
        Tcp {
            source_port: 40_000,
            destination_port: 80,
            ..Tcp::default()
        },
        request,
    )
}

fn conversation(protocol: Protocol) -> Conversation {
    Conversation::new(builtin::registry(), Spec::new(protocol))
}

#[test]
fn frame_limit_applies_before_any_frame_exists() {
    let big = vec![0_u8; 1460 * 2000];
    let error = conversation(Protocol::Tcp)
        .expand(&tcp_recipe(&big), &Bytes::from(big.clone()))
        .expect_err("more than 4096 frames");
    assert!(matches!(
        error,
        Error::FrameLimit { limit, .. } if limit == MAX_FRAMES
    ));
    assert_eq!(error.classification().code, "cli.conversation_limit");

    let lowered = Spec {
        max_frames: 8,
        ..Spec::new(Protocol::Tcp)
    };
    let error = Conversation::new(builtin::registry(), lowered)
        .expand(&tcp_recipe(b"x"), &Bytes::new())
        .expect_err("nine frames exceed a limit of eight");
    assert!(matches!(
        error,
        Error::FrameLimit {
            requested: 9,
            limit: 8
        }
    ));
}

#[test]
fn recipes_that_are_not_a_supported_conversation_are_refused() {
    let udp = recipe(Udp::default(), b"");
    assert!(matches!(
        conversation(Protocol::Tcp).expand(&udp, &Bytes::new()),
        Err(Error::Transport {
            expected: Protocol::Tcp
        })
    ));
    let mut tunneled = Packet::new();
    tunneled.push(Ipv4::default());
    tunneled.push(Ipv4::default());
    tunneled.push(Tcp::default());
    assert!(matches!(
        conversation(Protocol::Tcp).expand(&tunneled, &Bytes::new()),
        Err(Error::Transport { .. })
    ));
    let mut no_network = Packet::new();
    no_network.push(Ethernet::default());
    assert!(matches!(
        conversation(Protocol::Tcp).expand(&no_network, &Bytes::new()),
        Err(Error::MissingNetwork)
    ));
    let mut odd_link = Packet::new();
    odd_link.push(Raw::new(vec![1]));
    odd_link.push(Ipv4::default());
    let error = conversation(Protocol::Tcp)
        .expand(&odd_link, &Bytes::new())
        .expect_err("raw before IP");
    assert_eq!(error.classification().code, "cli.conversation_recipe");

    let zero_window = recipe(
        Tcp {
            window: 0,
            ..Tcp::default()
        },
        b"",
    );
    assert!(matches!(
        conversation(Protocol::Tcp).expand(&zero_window, &Bytes::new()),
        Err(Error::ZeroWindow)
    ));
    let narrow = recipe(
        Tcp {
            window: 1000,
            ..Tcp::default()
        },
        b"",
    );
    assert!(matches!(
        conversation(Protocol::Tcp).expand(&narrow, &Bytes::new()),
        Err(Error::MssExceedsWindow {
            mss: 1460,
            window: 1000
        })
    ));
    let zero_mss = Spec {
        mss: 0,
        ..Spec::new(Protocol::Tcp)
    };
    assert!(matches!(
        Conversation::new(builtin::registry(), zero_mss).expand(&tcp_recipe(b""), &Bytes::new()),
        Err(Error::ZeroMss)
    ));
}
