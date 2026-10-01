// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use std::io::Cursor;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use packetcraftr_core::analysis::expert::Collector;
use packetcraftr_core::analysis::follow::{self, PeerDirection};
use packetcraftr_core::analysis::{Options, StreamRef, StreamTransport, run};
use packetcraftr_core::build::Builder;
use packetcraftr_core::capture_file::{Reader, Writer};
use packetcraftr_core::codec::{Context, Mode};
use packetcraftr_core::conversation::{
    Close, Conversation, DEFAULT_CLIENT_ISN, DEFAULT_SERVER_ISN, Error, MAX_FRAMES,
    Options as Spec, Protocol,
};
use packetcraftr_core::error::Classified;
use packetcraftr_core::expression;
use packetcraftr_core::frame::{Frame, LinkType};
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

fn tcp_layers(frames: &[Packet]) -> Vec<(&Tcp, usize)> {
    frames
        .iter()
        .map(|frame| {
            let payload = frame.get::<Raw>().map_or(0, |raw| raw.bytes.len());
            (frame.get::<Tcp>().expect("TCP frame"), payload)
        })
        .collect()
}

fn built_frames(frames: Vec<Packet>) -> Vec<Frame> {
    let builder = Builder::new(builtin::registry());
    frames
        .into_iter()
        .enumerate()
        .map(|(ordinal, frame)| {
            let built = builder
                .build(frame, Context::default(), Default::default())
                .expect("conversation frames build");
            let timestamp = SystemTime::UNIX_EPOCH + Duration::from_millis(ordinal as u64);
            Frame::new(timestamp, LinkType::ETHERNET, built.bytes).expect("valid frame")
        })
        .collect()
}

fn capture(frames: &[Frame]) -> Reader<Cursor<Vec<u8>>> {
    let mut writer = Writer::pcap(Vec::new(), LinkType::ETHERNET).expect("writer");
    for frame in frames {
        writer.write_frame(frame).expect("frame writes");
    }
    Reader::new(Cursor::new(writer.into_inner())).expect("capture opens")
}

#[test]
fn tcp_conversation_has_consistent_sequence_space_and_clean_analysis() {
    let request = (0..3000_u32).map(|value| value as u8).collect::<Vec<_>>();
    let response = Bytes::from_iter((0..100_u8).map(|value| value ^ 0x5a));
    let frames = conversation(Protocol::Tcp)
        .expand(&tcp_recipe(&request), &response)
        .expect("conversation expands");

    let layers = tcp_layers(&frames);
    let (c, s) = (DEFAULT_CLIENT_ISN, DEFAULT_SERVER_ISN);
    // Handshake, three request segments and their ACK, the response and its
    // ACK, then the four-frame FIN exchange.
    let expected: [(u16, u32, u32, usize); 13] = [
        (Tcp::SYN, c, 0, 0),
        (Tcp::SYN | Tcp::ACK, s, c + 1, 0),
        (Tcp::ACK, c + 1, s + 1, 0),
        (Tcp::ACK, c + 1, s + 1, 1460),
        (Tcp::ACK, c + 1461, s + 1, 1460),
        (Tcp::ACK | 0x008, c + 2921, s + 1, 80),
        (Tcp::ACK, s + 1, c + 3001, 0),
        (Tcp::ACK | 0x008, s + 1, c + 3001, 100),
        (Tcp::ACK, c + 3001, s + 101, 0),
        (Tcp::FIN | Tcp::ACK, c + 3001, s + 101, 0),
        (Tcp::ACK, s + 101, c + 3002, 0),
        (Tcp::FIN | Tcp::ACK, s + 101, c + 3002, 0),
        (Tcp::ACK, c + 3002, s + 102, 0),
    ];
    assert_eq!(layers.len(), expected.len());
    for (index, ((tcp, payload), (flags, sequence, acknowledgment, length))) in
        layers.iter().zip(expected).enumerate()
    {
        assert_eq!(
            (tcp.flags, tcp.sequence, tcp.acknowledgment, *payload),
            (flags, sequence, acknowledgment, length),
            "frame {}",
            index + 1
        );
    }

    let ethernet = |frame: &Packet| {
        let layer = frame.get::<Ethernet>().expect("Ethernet");
        (layer.source, layer.destination)
    };
    assert_eq!(ethernet(&frames[0]), (CLIENT_MAC, SERVER_MAC));
    assert_eq!(ethernet(&frames[1]), (SERVER_MAC, CLIENT_MAC));
    let ip = frames[1].get::<Ipv4>().expect("IPv4");
    assert_eq!((ip.source, ip.destination), (SERVER_IP, CLIENT_IP));
    assert_eq!(
        (layers[1].0.source_port, layers[1].0.destination_port),
        (80, 40_000)
    );

    let frames = built_frames(frames);
    let mut findings = Vec::new();
    let mut collector = Collector::new();
    let summary = run(
        &mut capture(&frames),
        builtin::registry(),
        &Options {
            tcp_events: true,
            ..Options::default()
        },
        |record| {
            findings.extend(collector.observe(&record));
            Ok(())
        },
    )
    .expect("expert pass");
    let (trailing, _) = collector.finish(&summary);
    findings.extend(trailing);
    assert!(findings.is_empty(), "{findings:?}");

    let mut follower = follow::Collector::new(StreamRef {
        transport: StreamTransport::Tcp,
        index: 0,
    });
    let mut chunks = Vec::new();
    let summary = run(
        &mut capture(&frames),
        builtin::registry(),
        &Options {
            tcp_events: true,
            ..Options::default()
        },
        |record| {
            chunks.extend(follower.observe(&record));
            Ok(())
        },
    )
    .expect("follow pass");
    follower.finish(&summary);
    let joined = |direction| {
        chunks
            .iter()
            .filter(|chunk| chunk.direction == direction)
            .flat_map(|chunk| chunk.bytes.iter().copied())
            .collect::<Vec<_>>()
    };
    assert_eq!(joined(PeerDirection::ClientToServer), request);
    assert_eq!(joined(PeerDirection::ServerToClient), response.to_vec());
}

#[test]
fn equal_inputs_produce_identical_frames_and_options_change_them() {
    let build = |options: Spec| {
        let frames = Conversation::new(builtin::registry(), options)
            .expand(
                &tcp_recipe(b"GET / HTTP/1.1\r\n\r\n"),
                &Bytes::from_static(b"ok"),
            )
            .expect("expands");
        built_frames(frames)
            .into_iter()
            .map(|frame| frame.bytes().to_vec())
            .collect::<Vec<_>>()
    };
    let options = Spec::new(Protocol::Tcp);
    assert_eq!(build(options), build(options));
    let moved = Spec {
        client_isn: 7,
        ..options
    };
    assert_ne!(build(options), build(moved));
}

#[test]
fn close_modes_end_the_flow_as_requested() {
    let frames = |close| {
        let options = Spec {
            close,
            ..Spec::new(Protocol::Tcp)
        };
        Conversation::new(builtin::registry(), options)
            .expand(&tcp_recipe(b"hello"), &Bytes::new())
            .expect("expands")
    };
    let fin = frames(Close::Fin);
    let rst = frames(Close::Rst);
    let open = frames(Close::None);
    assert_eq!(
        (fin.len(), rst.len(), open.len()),
        (3 + 2 + 4, 3 + 2 + 1, 3 + 2)
    );
    let last = |frames: &[Packet]| {
        let layers = tcp_layers(frames);
        let (tcp, _) = layers.last().expect("frames");
        tcp.flags
    };
    assert_eq!(last(&rst), Tcp::RST | Tcp::ACK);
    assert_eq!(last(&open), Tcp::ACK);
    assert_eq!(last(&fin), Tcp::ACK);
    assert!(tcp_layers(&fin)[5].0.flags & Tcp::FIN != 0);
}

#[test]
fn data_stays_within_the_advertised_window() {
    let options = Spec {
        mss: 100,
        close: Close::None,
        ..Spec::new(Protocol::Tcp)
    };
    let recipe = recipe(
        Tcp {
            window: 250,
            ..Tcp::default()
        },
        &[7; 500],
    );
    let frames = Conversation::new(builtin::registry(), options)
        .expand(&recipe, &Bytes::new())
        .expect("expands");
    let layers = tcp_layers(&frames);
    let mut outstanding = 0_u32;
    let mut peak = 0_u32;
    for (_, payload) in &layers[3..] {
        if *payload > 0 {
            outstanding += *payload as u32;
            peak = peak.max(outstanding);
        } else {
            outstanding = 0;
        }
    }
    assert!(peak <= 250, "{peak}");
    // Five segments, acknowledged after every second one and at the end.
    assert_eq!(layers.len(), 3 + 5 + 3);
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
fn udp_conversation_swaps_endpoints_and_checksums_validly() {
    let recipe = recipe(
        Udp {
            source_port: 41_000,
            destination_port: 5300,
            ..Udp::default()
        },
        b"query",
    );
    let frames = conversation(Protocol::Udp)
        .expand(&recipe, &Bytes::from_static(b"answer"))
        .expect("expands");
    assert_eq!(frames.len(), 2);
    let ports = |frame: &Packet| {
        let udp = frame.get::<Udp>().expect("UDP");
        (udp.source_port, udp.destination_port)
    };
    assert_eq!(ports(&frames[0]), (41_000, 5300));
    assert_eq!(ports(&frames[1]), (5300, 41_000));
    assert_eq!(frames[1].get::<Raw>().unwrap().bytes.as_ref(), b"answer");
    let ip = frames[1].get::<Ipv4>().expect("IPv4");
    assert_eq!((ip.source, ip.destination), (SERVER_IP, CLIENT_IP));

    for frame in built_frames(frames) {
        let bytes = frame.bytes();
        let (ip, udp) = bytes[14..].split_at(20);
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&ip[12..20]);
        pseudo.extend_from_slice(&[0, 17]);
        pseudo.extend_from_slice(&u16::try_from(udp.len()).unwrap().to_be_bytes());
        assert_eq!(
            packetcraftr_core::protocol::checksum_parts(&[&pseudo, udp]),
            0
        );
    }

    let silent = conversation(Protocol::Udp)
        .expand(&recipe, &Bytes::new())
        .expect("expands");
    assert_eq!(silent.len(), 1);
}

#[test]
fn both_initial_sequence_numbers_apply_and_wrap() {
    let options = Spec {
        client_isn: u32::MAX,
        server_isn: 7,
        close: Close::None,
        ..Spec::new(Protocol::Tcp)
    };
    let frames = Conversation::new(builtin::registry(), options)
        .expand(&tcp_recipe(b"hello"), &Bytes::from_static(b"ok"))
        .expect("expands");
    let layers = tcp_layers(&frames);
    let sequence = |index: usize| layers[index].0.sequence;
    let acknowledgment = |index: usize| layers[index].0.acknowledgment;
    // SYN, SYN/ACK, ACK, request, its ACK, response, its ACK.
    assert_eq!(frames.len(), 7);
    assert_eq!((sequence(0), sequence(1)), (u32::MAX, 7));
    assert_eq!(acknowledgment(1), 0);
    assert_eq!((sequence(2), acknowledgment(2)), (0, 8));
    assert_eq!((sequence(3), sequence(4)), (0, 8));
    assert_eq!(acknowledgment(4), 5);
    assert_eq!((sequence(5), acknowledgment(5)), (8, 5));
    assert_eq!((sequence(6), acknowledgment(6)), (5, 10));
}

#[test]
fn a_typed_udp_request_keeps_its_layers_on_a_registered_port() {
    let registry = builtin::registry();
    let recipe = expression::parse(
        "ethernet()/ipv4(src=192.0.2.1,dst=198.51.100.2)/udp(sport=4000,dport=53)/dns(id=1)",
        &registry,
        Default::default(),
    )
    .expect("recipe parses");
    let build = |frame: Packet, mode: Mode| {
        let options = packetcraftr_core::build::Options {
            mode,
            ..Default::default()
        };
        Builder::new(builtin::registry()).build(frame, Context::default(), options)
    };

    let query = conversation(Protocol::Udp)
        .expand(&recipe, &Bytes::new())
        .expect("expands");
    let protocols = query[0]
        .iter()
        .map(|layer| layer.protocol_id().as_str())
        .collect::<Vec<_>>();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp", "dns"]);
    let strict = build(query[0].clone(), Mode::Strict).expect("the typed query builds strictly");
    let plain = build(recipe.clone(), Mode::Strict).expect("the recipe builds on its own");
    assert_eq!(strict.bytes, plain.bytes);

    // The response is raw bytes, which strict mode refuses on the registered port.
    let frames = conversation(Protocol::Udp)
        .expand(&recipe, &Bytes::from_static(b"answer"))
        .expect("expands");
    assert_eq!(frames.len(), 2);
    build(frames[0].clone(), Mode::Strict).expect("the typed query still builds");
    build(frames[1].clone(), Mode::Strict).expect_err("raw bytes on port 53 are refused");
    let permissive = build(frames[1].clone(), Mode::Permissive).expect("permissive builds");
    assert!(
        permissive
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.udp_encapsulation_port")
    );
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
