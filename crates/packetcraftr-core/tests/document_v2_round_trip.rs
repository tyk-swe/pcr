// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use packetcraftr_core::Packet;
use packetcraftr_core::analysis::pcap::Reader;
use packetcraftr_core::build::{Builder, Context, DEFAULT_MAX_LAYERS, Mode, Options};
use packetcraftr_core::decode::{Dissector, Options as DecodeOptions};
use packetcraftr_core::document::v2::{Document, Minimized};
use packetcraftr_core::document::{DEFAULT_MAX_DOCUMENT_BYTES, Format};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::application::Dns;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::capture::{BsdLoop, BsdNull, LinuxSll, LinuxSll2};
use packetcraftr_core::protocol::gre::Gre;
use packetcraftr_core::protocol::icmp::{Icmpv4, Icmpv6};
use packetcraftr_core::protocol::ipv6::{
    DestinationOptions, Fragment, HopByHop, SegmentRoutingHeader,
};
use packetcraftr_core::protocol::link::{Arp, Ethernet, Llc, Snap, Vlan};
use packetcraftr_core::protocol::network::{Igmp, Ipv4, Ipv6};
use packetcraftr_core::protocol::support::BUILTIN_PROTOCOLS;
use packetcraftr_core::protocol::transport::{Sctp, Tcp, Udp};
use packetcraftr_core::protocol::tunnel::{
    Ah, Erspan, Esp, Geneve, L2tpv3, Mpls, Ppp, Pppoe, Vxlan,
};
use packetcraftr_core::registry::Registry;

/// Known round-trip failures due to library bugs (format: "case_name: reason").
const KNOWN_FAILURES: &[&str] = &[];

const ROOT_LINK_TYPE: LinkType = LinkType(u32::MAX);

fn default_registry() -> Arc<Registry> {
    Arc::new(builtin::registry().expect("built-in registry should be valid"))
}

fn rooted_registry(root: &str) -> Arc<Registry> {
    Arc::new(
        builtin::registry_with(|builder| {
            builder.bind_link_type(ROOT_LINK_TYPE.0, root)?;
            Ok(())
        })
        .unwrap_or_else(|error| panic!("{root} root binding: {error}")),
    )
}

#[derive(Clone)]
struct CorpusFrame {
    corpus: &'static str,
    name: String,
    frame: Frame,
    registry: Arc<Registry>,
}

#[derive(Clone, Debug)]
struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: usize) -> Self {
        let seed_u64 = u64::try_from(seed).unwrap_or(0);
        let s = seed_u64
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(0x517C_C1B7_2722_0A95);
        Self(if s == 0 { 0x517C_C1B7_2722_0A95 } else { s })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_usize(&mut self, upper_bound: usize) -> usize {
        if upper_bound == 0 {
            0
        } else {
            let bound_u64 = u64::try_from(upper_bound).unwrap_or(u64::MAX);
            usize::try_from(self.next_u64() % bound_u64).unwrap_or(0)
        }
    }

    fn next_u8(&mut self) -> u8 {
        u8::try_from(self.next_u64() & 0xff).unwrap_or(0xff)
    }
}

fn ipv4(source: [u8; 4], destination: [u8; 4]) -> Ipv4 {
    Ipv4 {
        source: Ipv4Addr::from(source),
        destination: Ipv4Addr::from(destination),
        ..Ipv4::default()
    }
}

fn ipv6(source: &str, destination: &str) -> Ipv6 {
    Ipv6 {
        source: source.parse().expect("source address"),
        destination: destination.parse().expect("destination address"),
        ..Ipv6::default()
    }
}

fn ipv4_source_route(option: u8, pointer: u8, addresses: &[Ipv4Addr]) -> Bytes {
    let length = 3usize
        .checked_add(addresses.len().checked_mul(4).expect("route length fits"))
        .expect("route length fits");
    let mut bytes = Vec::with_capacity(length);
    bytes.push(option);
    bytes.push(u8::try_from(length).expect("IPv4 option length fits u8"));
    bytes.push(pointer);
    for address in addresses {
        bytes.extend_from_slice(&address.octets());
    }
    Bytes::from(bytes)
}

fn source_routed_ipv4(option: u8, pointer: u8, addresses: &[Ipv4Addr]) -> Ipv4 {
    Ipv4 {
        source: Ipv4Addr::new(192, 0, 2, 10),
        destination: Ipv4Addr::new(203, 0, 113, 10),
        options: ipv4_source_route(option, pointer, addresses),
        ..Ipv4::default()
    }
}

fn known_tcp() -> Tcp {
    Tcp {
        source_port: 12_345,
        destination_port: 80,
        sequence: 1,
        window: 0xfaf0,
        ..Tcp::default()
    }
}

fn known_udp() -> Udp {
    Udp {
        source_port: 12_345,
        destination_port: 53,
        ..Udp::default()
    }
}

/// (1) Every builtin's default wire image.
fn load_builtin_defaults_corpus() -> Vec<CorpusFrame> {
    let registry = default_registry();
    let builder = Builder::new(Arc::clone(&registry));
    let mut frames = Vec::new();

    for support in BUILTIN_PROTOCOLS
        .iter()
        .filter(|support| support.build && support.dissect && support.exact_round_trip)
    {
        let codec = registry
            .codec(support.protocol)
            .expect("codec should exist");
        let mut packet = Packet::new();
        let Ok(layer) = codec.make_layer(&BTreeMap::new()) else {
            continue;
        };
        packet.push_boxed(layer);
        let Ok(first) = builder.build(packet, Context::default(), Options::default()) else {
            continue;
        };
        let frame = Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, first.bytes)
            .unwrap_or_else(|error| panic!("{} default frame failed: {error}", support.protocol));
        frames.push(CorpusFrame {
            corpus: "builtin_defaults",
            name: format!("builtin_{}", support.protocol),
            frame,
            registry: rooted_registry(support.protocol),
        });
    }

    frames
}

/// (2) Every frame in `examples/captures/*.pcapng`.
fn load_captures_corpus() -> Vec<CorpusFrame> {
    let default_reg = default_registry();
    let mut frames = Vec::new();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/captures");
    let mut entries = Vec::new();
    if let Ok(read_dir) = std::fs::read_dir(&dir) {
        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("pcapng") {
                entries.push(path);
            }
        }
    }
    entries.sort();

    for path in entries {
        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let file = std::fs::File::open(&path)
            .unwrap_or_else(|e| panic!("failed to open {}: {e}", path.display()));
        let mut reader = Reader::new(std::io::BufReader::new(file))
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        let mut frame_idx = 0;
        while let Some(frame) = reader
            .next_frame()
            .unwrap_or_else(|e| panic!("frame error in {}: {e}", path.display()))
        {
            frames.push(CorpusFrame {
                corpus: "captures",
                name: format!("{file_name}#{frame_idx}"),
                frame,
                registry: Arc::clone(&default_reg),
            });
            frame_idx += 1;
        }
    }

    frames
}

/// (3) The fixtures in `crates/packetcraftr-core/tests/protocol_end_to_end.rs`.
fn load_protocol_end_to_end_corpus() -> Vec<CorpusFrame> {
    let default_reg = default_registry();
    let builder = Builder::new(Arc::clone(&default_reg));
    let mut frames = Vec::new();

    // 1. ipv4_source_route_decode_accepts_known_transport_checksums
    let v_tcp = packetcraftr_core::protocol::raw::parse_hex(
        "47000030123400004006cc3bc000020acb00710a830704cb007114003039005000000001000000005002faf086480000",
    ).expect("hex");
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_source_route_known_tcp".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, v_tcp).unwrap(),
        registry: Arc::clone(&default_reg),
    });

    let v_udp = packetcraftr_core::protocol::raw::parse_hex(
        "4700002c123500004011cc33c000020acb00710a830704cb00711400303900350010902a5043522d4c535252",
    )
    .expect("hex");
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_source_route_known_udp".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, v_udp).unwrap(),
        registry: Arc::clone(&default_reg),
    });

    // 2. ipv4_source_route_encode_matches_known_transport_checksums
    let final_destination = Ipv4Addr::new(203, 0, 113, 20);
    let mut tcp_packet = Packet::new();
    tcp_packet.push(Ipv4 {
        identification: 0x1234,
        ..source_routed_ipv4(131, 4, &[final_destination])
    });
    tcp_packet.push(known_tcp());
    let tcp_built = builder
        .build(tcp_packet, Context::default(), Options::default())
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_source_route_encode_tcp".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, tcp_built.bytes).unwrap(),
        registry: rooted_registry("ipv4"),
    });

    let mut udp_packet = Packet::new();
    udp_packet.push(Ipv4 {
        identification: 0x1235,
        ..source_routed_ipv4(131, 4, &[final_destination])
    });
    udp_packet.push(known_udp());
    udp_packet.push(Raw::new(b"PCR-LSRR".to_vec()));
    let udp_built = builder
        .build(
            udp_packet,
            Context::default(),
            Options {
                mode: Mode::Permissive,
                ..Options::default()
            },
        )
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_source_route_encode_udp".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, udp_built.bytes).unwrap(),
        registry: rooted_registry("ipv4"),
    });

    // 3. assert_remaining_source_route_checksums
    let first_remaining = Ipv4Addr::new(203, 0, 113, 20);
    let final_dest_30 = Ipv4Addr::new(203, 0, 113, 30);
    let mut tcp_multiple_lsrr = Packet::new();
    tcp_multiple_lsrr.push(source_routed_ipv4(
        131,
        4,
        &[first_remaining, final_dest_30],
    ));
    tcp_multiple_lsrr.push(known_tcp());
    let tcp_multiple_built = builder
        .build(tcp_multiple_lsrr, Context::default(), Options::default())
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_source_route_remaining_tcp".to_owned(),
        frame: Frame::new(
            SystemTime::UNIX_EPOCH,
            ROOT_LINK_TYPE,
            tcp_multiple_built.bytes,
        )
        .unwrap(),
        registry: rooted_registry("ipv4"),
    });

    let mut udp_multiple_ssrr = Packet::new();
    udp_multiple_ssrr.push(source_routed_ipv4(
        137,
        4,
        &[first_remaining, final_dest_30],
    ));
    udp_multiple_ssrr.push(known_udp());
    udp_multiple_ssrr.push(Raw::new(b"PCR-LSRR".to_vec()));
    let udp_multiple_built = builder
        .build(
            udp_multiple_ssrr,
            Context::default(),
            Options {
                mode: Mode::Permissive,
                ..Options::default()
            },
        )
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_source_route_remaining_udp".to_owned(),
        frame: Frame::new(
            SystemTime::UNIX_EPOCH,
            ROOT_LINK_TYPE,
            udp_multiple_built.bytes,
        )
        .unwrap(),
        registry: rooted_registry("ipv4"),
    });

    // 4. assert_completed_source_route_checksums
    let mut tcp_completed_ssrr = Packet::new();
    tcp_completed_ssrr.push(source_routed_ipv4(137, 8, &[first_remaining]));
    tcp_completed_ssrr.push(known_tcp());
    let tcp_completed_built = builder
        .build(tcp_completed_ssrr, Context::default(), Options::default())
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_source_route_completed_tcp".to_owned(),
        frame: Frame::new(
            SystemTime::UNIX_EPOCH,
            ROOT_LINK_TYPE,
            tcp_completed_built.bytes,
        )
        .unwrap(),
        registry: rooted_registry("ipv4"),
    });

    let mut udp_completed_lsrr = Packet::new();
    udp_completed_lsrr.push(source_routed_ipv4(131, 8, &[first_remaining]));
    udp_completed_lsrr.push(known_udp());
    udp_completed_lsrr.push(Raw::new(b"PCR-LSRR".to_vec()));
    let udp_completed_built = builder
        .build(
            udp_completed_lsrr,
            Context::default(),
            Options {
                mode: Mode::Permissive,
                ..Options::default()
            },
        )
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_source_route_completed_udp".to_owned(),
        frame: Frame::new(
            SystemTime::UNIX_EPOCH,
            ROOT_LINK_TYPE,
            udp_completed_built.bytes,
        )
        .unwrap(),
        registry: rooted_registry("ipv4"),
    });

    // 5. ipv4_source_route_transport_checksums_cover_route_states_and_nearest_envelope
    let mut nested = Packet::new();
    nested.push(Ipv4 {
        source: Ipv4Addr::new(10, 0, 0, 1),
        destination: Ipv4Addr::new(10, 0, 0, 2),
        options: ipv4_source_route(131, 4, &[Ipv4Addr::new(10, 0, 0, 9)]),
        ..Ipv4::default()
    });
    nested.push(source_routed_ipv4(137, 8, &[first_remaining]));
    nested.push(known_tcp());
    let nested_built = builder
        .build(nested, Context::default(), Options::default())
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_source_route_nested".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, nested_built.bytes).unwrap(),
        registry: rooted_registry("ipv4"),
    });

    // 6. filter_fixture
    let mut filter_pkt = Packet::new();
    filter_pkt.push(Ethernet {
        destination: [0, 1, 2, 3, 4, 5],
        source: [6, 7, 8, 9, 10, 11],
        ..Ethernet::default()
    });
    filter_pkt.push(Ipv4 {
        options: Bytes::from_static(&[1, 1, 0]),
        ..ipv4([192, 0, 2, 1], [198, 51, 100, 2])
    });
    filter_pkt.push(Udp {
        source_port: 12_345,
        destination_port: 9_999,
        ..Udp::default()
    });
    filter_pkt.push(Raw::new(b"hello-filter".to_vec()));
    let filter_built = builder
        .build(filter_pkt, Context::default(), Options::default())
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_filter_fixture".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, filter_built.bytes).unwrap(),
        registry: rooted_registry("ethernet"),
    });

    // 7. ipv6_extensions_tcp_and_segment_routing_round_trip
    let mut extension_packet = Packet::new();
    extension_packet.push(ipv6("2001:db8::1", "2001:db8::2"));
    extension_packet.push(HopByHop {
        options: Bytes::from_static(&[0, 0, 1]),
        ..HopByHop::default()
    });
    extension_packet.push(DestinationOptions {
        options: Bytes::from_static(&[1, 0]),
        ..DestinationOptions::default()
    });
    extension_packet.push(Fragment::default());
    extension_packet.push(Tcp {
        source_port: 40_000,
        destination_port: 443,
        sequence: 99,
        flags: Tcp::SYN | Tcp::ACK,
        options: Bytes::from_static(&[1, 1, 1]),
        ..Tcp::default()
    });
    extension_packet.push(Raw::new(b"tls".to_vec()));
    let ext_built = builder
        .build(extension_packet, Context::default(), Options::default())
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_ipv6_extensions_tcp".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, ext_built.bytes).unwrap(),
        registry: rooted_registry("ipv6"),
    });

    let srh_final_dst: Ipv6Addr = "2001:db8::99".parse().expect("segment");
    let srh_active: Ipv6Addr = "2001:db8::2".parse().expect("segment");
    let mut srh_packet = Packet::new();
    srh_packet.push(ipv6("2001:db8::1", "2001:db8::2"));
    srh_packet.push(SegmentRoutingHeader {
        segments: vec![srh_active, srh_final_dst],
        ..SegmentRoutingHeader::default()
    });
    srh_packet.push(Udp {
        source_port: 5_000,
        destination_port: 5_001,
        ..Udp::default()
    });
    srh_packet.push(Raw::new(vec![1, 2, 3, 4]));
    let srh_built = builder
        .build(srh_packet, Context::default(), Options::default())
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_ipv6_srh_udp".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, srh_built.bytes).unwrap(),
        registry: rooted_registry("ipv6"),
    });

    // 8. link_capture_and_raw_ip_roots_round_trip
    let mut llc = Packet::new();
    llc.push(Ethernet::default());
    llc.push(Llc::default());
    llc.push(Snap::default());
    llc.push(ipv4([10, 0, 0, 1], [10, 0, 0, 2]));
    llc.push(Icmpv4::default());
    let llc_built = builder
        .build(llc, Context::default(), Options::default())
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_llc_snap_icmp".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, llc_built.bytes).unwrap(),
        registry: rooted_registry("ethernet"),
    });

    let mut vlan = Packet::new();
    vlan.push(Ethernet::default());
    vlan.push(Vlan {
        priority: 7,
        drop_eligible: true,
        vlan_id: 4094,
        ..Vlan::default()
    });
    vlan.push(Arp {
        sender_protocol: Ipv4Addr::new(192, 0, 2, 10),
        target_protocol: Ipv4Addr::new(192, 0, 2, 1),
        ..Arp::default()
    });
    let vlan_built = builder
        .build(vlan, Context::default(), Options::default())
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_vlan_arp".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, vlan_built.bytes).unwrap(),
        registry: rooted_registry("ethernet"),
    });

    let roots: Vec<(Box<dyn packetcraftr_core::layer::Layer>, &str)> = vec![
        (Box::new(BsdNull::default()), "bsd_null"),
        (Box::new(BsdLoop::default()), "bsd_loop"),
        (Box::new(LinuxSll::default()), "linux_sll"),
        (Box::new(LinuxSll2::default()), "linux_sll2"),
    ];
    for (root_layer, name) in roots {
        let mut pkt = Packet::new();
        pkt.push_boxed(root_layer);
        pkt.push(ipv4([203, 0, 113, 1], [203, 0, 113, 2]));
        pkt.push(Icmpv4::default());
        let built = builder
            .build(pkt, Context::default(), Options::default())
            .unwrap();
        frames.push(CorpusFrame {
            corpus: "protocol_end_to_end",
            name: format!("e2e_root_{name}"),
            frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, built.bytes).unwrap(),
            registry: rooted_registry(name),
        });
    }

    let mut raw_ip_pkt = Packet::new();
    raw_ip_pkt.push(ipv4([192, 0, 2, 1], [198, 51, 100, 1]));
    raw_ip_pkt.push(Icmpv4::default());
    let raw_ip_built = builder
        .build(raw_ip_pkt, Context::default(), Options::default())
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_raw_ip_dlt_raw".to_owned(),
        frame: Frame::new(
            SystemTime::UNIX_EPOCH,
            LinkType::RAW,
            raw_ip_built.bytes.clone(),
        )
        .unwrap(),
        registry: Arc::clone(&default_reg),
    });
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_raw_ip_dlt_bsd_raw".to_owned(),
        frame: Frame::new(
            SystemTime::UNIX_EPOCH,
            LinkType::BSD_RAW,
            raw_ip_built.bytes,
        )
        .unwrap(),
        registry: Arc::clone(&default_reg),
    });

    // 9. overlay_and_security_tunnel_stacks_round_trip
    let mut vxlan = Packet::new();
    vxlan.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    vxlan.push(Udp {
        source_port: 50_000,
        destination_port: 4_789,
        ..Udp::default()
    });
    vxlan.push(Vxlan {
        vni: 0x12345,
        ..Vxlan::default()
    });
    vxlan.push(Ethernet::default());
    vxlan.push(ipv4([10, 0, 0, 1], [10, 0, 0, 2]));
    vxlan.push(Icmpv4::default());
    let vxlan_built = builder
        .build(vxlan, Context::default(), Options::default())
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_overlay_vxlan".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, vxlan_built.bytes).unwrap(),
        registry: rooted_registry("ipv4"),
    });

    let mut geneve = Packet::new();
    geneve.push(ipv6("2001:db8::1", "2001:db8::2"));
    geneve.push(Udp {
        source_port: 50_000,
        destination_port: 6_081,
        ..Udp::default()
    });
    geneve.push(Geneve {
        vni: 77,
        ..Geneve::default()
    });
    geneve.push(ipv4([172, 16, 0, 1], [172, 16, 0, 2]));
    geneve.push(Icmpv4::default());
    let geneve_built = builder
        .build(geneve, Context::default(), Options::default())
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_overlay_geneve".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, geneve_built.bytes).unwrap(),
        registry: rooted_registry("ipv6"),
    });

    let mut gre = Packet::new();
    gre.push(ipv4([198, 51, 100, 1], [198, 51, 100, 2]));
    gre.push(Gre {
        checksum: Some(Default::default()),
        key: Some(7),
        sequence: Some(9),
        ..Gre::default()
    });
    gre.push(Erspan::default());
    gre.push(Ethernet::default());
    gre.push(Arp::default());
    let gre_built = builder
        .build(gre, Context::default(), Options::default())
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_overlay_gre_erspan".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, gre_built.bytes).unwrap(),
        registry: rooted_registry("ipv4"),
    });

    let mut mpls = Packet::new();
    mpls.push(Ethernet::default());
    mpls.push(Mpls {
        label: 16,
        bottom_of_stack: false,
        ..Mpls::default()
    });
    mpls.push(Mpls {
        label: 32,
        ..Mpls::default()
    });
    mpls.push(ipv4([10, 1, 0, 1], [10, 1, 0, 2]));
    mpls.push(Icmpv4::default());
    let mpls_built = builder
        .build(mpls, Context::default(), Options::default())
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_stack_mpls".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, mpls_built.bytes).unwrap(),
        registry: rooted_registry("ethernet"),
    });

    let mut pppoe = Packet::new();
    pppoe.push(Ethernet::default());
    pppoe.push(Pppoe {
        session_id: 4,
        ..Pppoe::default()
    });
    pppoe.push(Ppp::default());
    pppoe.push(ipv6("2001:db8:1::1", "2001:db8:1::2"));
    pppoe.push(Icmpv6::default());
    let pppoe_built = builder
        .build(pppoe, Context::default(), Options::default())
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_stack_pppoe".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, pppoe_built.bytes).unwrap(),
        registry: rooted_registry("ethernet"),
    });

    let mut ah = Packet::new();
    ah.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    ah.push(Ah::default());
    ah.push(Udp {
        source_port: 10,
        destination_port: 11,
        ..Udp::default()
    });
    ah.push(Raw::new(vec![1, 2, 3]));
    let ah_built = builder
        .build(ah, Context::default(), Options::default())
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_stack_ah".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, ah_built.bytes).unwrap(),
        registry: rooted_registry("ipv4"),
    });

    let mut esp = Packet::new();
    esp.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    esp.push(Esp::default());
    esp.push(Raw::new(vec![0xaa, 0xbb, 0, 59]));
    let esp_built = builder
        .build(esp, Context::default(), Options::default())
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_stack_esp".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, esp_built.bytes).unwrap(),
        registry: rooted_registry("ipv4"),
    });

    let mut l2tp = Packet::new();
    l2tp.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    l2tp.push(L2tpv3 { session_id: 42 });
    l2tp.push(Raw::new(vec![1, 2, 3, 4]));
    let l2tp_built = builder
        .build(l2tp, Context::default(), Options::default())
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_stack_l2tp".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, l2tp_built.bytes).unwrap(),
        registry: rooted_registry("ipv4"),
    });

    // 10. sctp_dns_and_malformed_inputs_cover_bounded_parsers
    let init_chunk = vec![
        1, 0, 0, 20, 0, 0, 0, 7, 0, 0, 4, 0, 0, 10, 0, 10, 0, 1, 0, 1,
    ];
    let mut sctp = Packet::new();
    sctp.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    sctp.push(Sctp::default());
    sctp.push(Raw::new(init_chunk));
    let sctp_built = builder
        .build(sctp, Context::default(), Options::default())
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_sctp_init".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, sctp_built.bytes).unwrap(),
        registry: rooted_registry("ipv4"),
    });

    let query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 3, b'w', b'w',
        b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ];
    let dns = Dns::from_wire(query).expect("valid DNS query");
    let mut dns_pkt = Packet::new();
    dns_pkt.push(ipv4([192, 0, 2, 1], [8, 8, 8, 8]));
    dns_pkt.push(Udp::default());
    dns_pkt.push(dns);
    let dns_built = builder
        .build(dns_pkt, Context::default(), Options::default())
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_dns_query".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, dns_built.bytes).unwrap(),
        registry: rooted_registry("ipv4"),
    });

    for (root, bytes) in [
        ("ethernet", vec![0; 13]),
        ("ipv4", vec![0; 19]),
        ("ipv6", vec![0; 39]),
        ("udp", vec![0; 7]),
        ("tcp", vec![0; 19]),
        ("sctp", vec![0; 11]),
        ("dns", vec![0; 11]),
        ("geneve", vec![0; 7]),
        ("vxlan", vec![0; 7]),
        ("gre", vec![0; 3]),
    ] {
        frames.push(CorpusFrame {
            corpus: "protocol_end_to_end",
            name: format!("e2e_malformed_{root}"),
            frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, bytes).unwrap(),
            registry: rooted_registry(root),
        });
    }

    // 11. typed_child_without_payload_is_preserved_as_malformed
    let mut empty_child_bytes = vec![0; 14];
    empty_child_bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_typed_child_empty".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, empty_child_bytes).unwrap(),
        registry: rooted_registry("ethernet"),
    });

    // 12. strict_and_permissive_modes_distinguish_noncanonical_wire_requests
    let mut invalid_ipv4 = Packet::new();
    invalid_ipv4.push(Ipv4 {
        reserved_flag: true,
        ..ipv4([192, 0, 2, 1], [192, 0, 2, 2])
    });
    invalid_ipv4.push(Icmpv4::default());
    let inv_ipv4_built = builder
        .build(
            invalid_ipv4,
            Context::default(),
            Options {
                mode: Mode::Permissive,
                ..Options::default()
            },
        )
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_permissive_ipv4_reserved".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, inv_ipv4_built.bytes).unwrap(),
        registry: rooted_registry("ipv4"),
    });

    let mut bad_vxlan = Packet::new();
    bad_vxlan.push(Vxlan {
        flags: 0,
        ..Vxlan::default()
    });
    bad_vxlan.push(Ethernet::default());
    let bad_vxlan_built = builder
        .build(
            bad_vxlan,
            Context::default(),
            Options {
                mode: Mode::Permissive,
                ..Options::default()
            },
        )
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_permissive_bad_vxlan".to_owned(),
        frame: Frame::new(
            SystemTime::UNIX_EPOCH,
            ROOT_LINK_TYPE,
            bad_vxlan_built.bytes,
        )
        .unwrap(),
        registry: rooted_registry("vxlan"),
    });

    let mut bad_arp = Packet::new();
    bad_arp.push(Arp {
        hardware_type: 2,
        ..Arp::default()
    });
    let bad_arp_built = builder
        .build(
            bad_arp,
            Context::default(),
            Options {
                mode: Mode::Permissive,
                ..Options::default()
            },
        )
        .unwrap();
    frames.push(CorpusFrame {
        corpus: "protocol_end_to_end",
        name: "e2e_permissive_bad_arp".to_owned(),
        frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, bad_arp_built.bytes).unwrap(),
        registry: rooted_registry("arp"),
    });

    // 13. corrupted_builtin_checksums_report_integrity_failures
    let mut chk_ipv4 = Packet::new();
    chk_ipv4.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    chk_ipv4.push(Icmpv4::default());

    let mut chk_tcp = Packet::new();
    chk_tcp.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    chk_tcp.push(known_tcp());

    let mut chk_udp = Packet::new();
    chk_udp.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    chk_udp.push(Udp {
        source_port: 12_345,
        destination_port: 40_000,
        ..Udp::default()
    });
    chk_udp.push(Raw::new(b"PCR!".to_vec()));

    let mut chk_sctp = Packet::new();
    chk_sctp.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    chk_sctp.push(Sctp::default());
    chk_sctp.push(Raw::new(vec![11, 0, 0, 4]));

    let mut chk_icmpv4 = Packet::new();
    chk_icmpv4.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    chk_icmpv4.push(Icmpv4::default());

    let mut chk_icmpv6 = Packet::new();
    chk_icmpv6.push(ipv6("2001:db8::1", "2001:db8::2"));
    chk_icmpv6.push(Icmpv6::default());

    let mut chk_igmp = Packet::new();
    chk_igmp.push(ipv4([192, 0, 2, 1], [224, 0, 0, 1]));
    chk_igmp.push(Igmp::default());

    let mut chk_gre = Packet::new();
    chk_gre.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    chk_gre.push(Gre {
        checksum: Some(Default::default()),
        key: Some(7),
        ..Gre::default()
    });
    chk_gre.push(Ethernet::default());
    chk_gre.push(Arp::default());

    let chk_cases = [
        ("corrupt_ipv4", "ipv4", chk_ipv4, 8),
        ("corrupt_tcp", "ipv4", chk_tcp, 38),
        ("corrupt_udp", "ipv4", chk_udp, 31),
        ("corrupt_sctp", "ipv4", chk_sctp, 24),
        ("corrupt_icmpv4", "ipv4", chk_icmpv4, 27),
        ("corrupt_icmpv6", "ipv6", chk_icmpv6, 47),
        ("corrupt_igmp", "ipv4", chk_igmp, 27),
        ("corrupt_gre", "ipv4", chk_gre, 28),
    ];

    for (case_name, root, pkt, corrupted_offset) in chk_cases {
        let built = builder
            .build(pkt, Context::default(), Options::default())
            .unwrap();
        let mut bytes = built.bytes.to_vec();
        bytes[corrupted_offset] ^= 0xff;
        frames.push(CorpusFrame {
            corpus: "protocol_end_to_end",
            name: format!("e2e_{case_name}"),
            frame: Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, bytes).unwrap(),
            registry: rooted_registry(root),
        });
    }

    frames
}

/// (4) Seeded mutations: 8 variants for each frame in (1)-(3).
fn generate_mutations(frames: &[CorpusFrame]) -> Vec<CorpusFrame> {
    let mut mutated = Vec::with_capacity(frames.len() * 8);

    for (frame_idx, item) in frames.iter().enumerate() {
        let original_bytes = item.frame.bytes();
        let mut rng = XorShift64::new(frame_idx);

        for variant_idx in 0..8 {
            let raw_mask = rng.next_u8();
            let mask = if raw_mask == 0 { 0xff } else { raw_mask };

            let mutated_bytes = if original_bytes.is_empty() {
                vec![mask]
            } else {
                let byte_pos = rng.next_usize(original_bytes.len());
                let mut bytes = original_bytes.to_vec();
                bytes[byte_pos] ^= mask;
                bytes
            };

            let frame = Frame::new(
                item.frame.timestamp.unwrap_or(SystemTime::UNIX_EPOCH),
                item.frame.link_type,
                mutated_bytes,
            )
            .expect("mutated frame must be constructible");

            mutated.push(CorpusFrame {
                corpus: "seeded_mutations",
                name: format!("{}_mut{variant_idx}", item.name),
                frame,
                registry: Arc::clone(&item.registry),
            });
        }
    }

    mutated
}

fn assert_frame_round_trip(item: &CorpusFrame) {
    if KNOWN_FAILURES.iter().any(|k| k.starts_with(&item.name)) {
        return;
    }

    let dissector = Dissector::new(Arc::clone(&item.registry));
    let decoded = dissector
        .decode(item.frame.clone(), DecodeOptions::default())
        .unwrap_or_else(|e| panic!("[{}] {} decode failed: {e}", item.corpus, item.name));

    let builder = Builder::new(Arc::clone(&item.registry));

    // 1. Minimized (full = false)
    let (doc_minimized, min_status) = Document::from_decoded(&decoded, &item.registry, false);

    // Stability assertion: emitting twice gives identical text
    let yaml_min_1 = doc_minimized
        .to_yaml_string()
        .unwrap_or_else(|e| panic!("[{}] {} to_yaml_string min: {e}", item.corpus, item.name));
    let yaml_min_2 = doc_minimized.to_yaml_string().unwrap_or_else(|e| {
        panic!(
            "[{}] {} to_yaml_string min second: {e}",
            item.corpus, item.name
        )
    });
    assert_eq!(
        yaml_min_1, yaml_min_2,
        "[{}] {} yaml min emit is unstable",
        item.corpus, item.name
    );

    let parsed_yaml_min = Document::parse(&yaml_min_1, Format::Yaml, DEFAULT_MAX_DOCUMENT_BYTES)
        .unwrap_or_else(|e| panic!("[{}] {} parse min yaml: {e}", item.corpus, item.name));
    let pkt_yaml_min = parsed_yaml_min
        .to_packet(&item.registry, DEFAULT_MAX_LAYERS)
        .unwrap_or_else(|e| panic!("[{}] {} to_packet min yaml: {e}", item.corpus, item.name));

    let json_min = doc_minimized
        .to_json_string()
        .unwrap_or_else(|e| panic!("[{}] {} to_json_string min: {e}", item.corpus, item.name));
    let parsed_json_min = Document::parse(&json_min, Format::Json, DEFAULT_MAX_DOCUMENT_BYTES)
        .unwrap_or_else(|e| panic!("[{}] {} parse min json: {e}", item.corpus, item.name));
    let pkt_json_min = parsed_json_min
        .to_packet(&item.registry, DEFAULT_MAX_LAYERS)
        .unwrap_or_else(|e| panic!("[{}] {} to_packet min json: {e}", item.corpus, item.name));

    match min_status {
        Minimized::Derived => {
            let built_yaml = builder
                .build(
                    pkt_yaml_min,
                    Context::default(),
                    Options {
                        mode: Mode::Strict,
                        ..Options::default()
                    },
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "[{}] {} strict build min yaml (Derived): {e}",
                        item.corpus, item.name
                    )
                });
            assert_eq!(
                built_yaml.bytes,
                item.frame.bytes(),
                "[{}] {} strict build min yaml bytes mismatch",
                item.corpus,
                item.name
            );

            let built_json = builder
                .build(
                    pkt_json_min,
                    Context::default(),
                    Options {
                        mode: Mode::Strict,
                        ..Options::default()
                    },
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "[{}] {} strict build min json (Derived): {e}",
                        item.corpus, item.name
                    )
                });
            assert_eq!(
                built_json.bytes,
                item.frame.bytes(),
                "[{}] {} strict build min json bytes mismatch",
                item.corpus,
                item.name
            );
        }
        Minimized::FullLiterals => {
            let built_yaml = builder
                .build(
                    pkt_yaml_min.clone(),
                    Context::default(),
                    Options {
                        mode: Mode::Permissive,
                        ..Options::default()
                    },
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "[{}] {} permissive build min yaml (FullLiterals): {e}",
                        item.corpus, item.name
                    )
                });
            assert_eq!(
                built_yaml.bytes,
                item.frame.bytes(),
                "[{}] {} permissive build min yaml bytes mismatch",
                item.corpus,
                item.name
            );

            if let Ok(strict_built) = builder.build(
                pkt_yaml_min,
                Context::default(),
                Options {
                    mode: Mode::Strict,
                    ..Options::default()
                },
            ) {
                assert_eq!(
                    strict_built.bytes,
                    item.frame.bytes(),
                    "[{}] {} strict build yaml matched with different bytes",
                    item.corpus,
                    item.name
                );
            }

            let built_json = builder
                .build(
                    pkt_json_min.clone(),
                    Context::default(),
                    Options {
                        mode: Mode::Permissive,
                        ..Options::default()
                    },
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "[{}] {} permissive build min json (FullLiterals): {e}",
                        item.corpus, item.name
                    )
                });
            assert_eq!(
                built_json.bytes,
                item.frame.bytes(),
                "[{}] {} permissive build min json bytes mismatch",
                item.corpus,
                item.name
            );

            if let Ok(strict_built) = builder.build(
                pkt_json_min,
                Context::default(),
                Options {
                    mode: Mode::Strict,
                    ..Options::default()
                },
            ) {
                assert_eq!(
                    strict_built.bytes,
                    item.frame.bytes(),
                    "[{}] {} strict build json matched with different bytes",
                    item.corpus,
                    item.name
                );
            }
        }
        Minimized::Skipped => {
            panic!(
                "[{}] {} full=false emitted Minimized::Skipped",
                item.corpus, item.name
            );
        }
    }

    // 2. Full (full = true)
    let (doc_full, full_status) = Document::from_decoded(&decoded, &item.registry, true);
    assert_eq!(
        full_status,
        Minimized::Skipped,
        "[{}] {} full=true must produce Minimized::Skipped",
        item.corpus,
        item.name
    );

    let yaml_full_1 = doc_full
        .to_yaml_string()
        .unwrap_or_else(|e| panic!("[{}] {} to_yaml_string full: {e}", item.corpus, item.name));
    let yaml_full_2 = doc_full.to_yaml_string().unwrap_or_else(|e| {
        panic!(
            "[{}] {} to_yaml_string full second: {e}",
            item.corpus, item.name
        )
    });
    assert_eq!(
        yaml_full_1, yaml_full_2,
        "[{}] {} yaml full emit is unstable",
        item.corpus, item.name
    );

    let parsed_yaml_full = Document::parse(&yaml_full_1, Format::Yaml, DEFAULT_MAX_DOCUMENT_BYTES)
        .unwrap_or_else(|e| panic!("[{}] {} parse full yaml: {e}", item.corpus, item.name));
    let pkt_yaml_full = parsed_yaml_full
        .to_packet(&item.registry, DEFAULT_MAX_LAYERS)
        .unwrap_or_else(|e| panic!("[{}] {} to_packet full yaml: {e}", item.corpus, item.name));
    let built_yaml_full = builder
        .build(
            pkt_yaml_full,
            Context::default(),
            Options {
                mode: Mode::Permissive,
                ..Options::default()
            },
        )
        .unwrap_or_else(|e| {
            panic!(
                "[{}] {} permissive build full yaml: {e}",
                item.corpus, item.name
            )
        });
    assert_eq!(
        built_yaml_full.bytes,
        item.frame.bytes(),
        "[{}] {} full yaml permissive bytes mismatch",
        item.corpus,
        item.name
    );

    let json_full = doc_full
        .to_json_string()
        .unwrap_or_else(|e| panic!("[{}] {} to_json_string full: {e}", item.corpus, item.name));
    let parsed_json_full = Document::parse(&json_full, Format::Json, DEFAULT_MAX_DOCUMENT_BYTES)
        .unwrap_or_else(|e| panic!("[{}] {} parse full json: {e}", item.corpus, item.name));
    let pkt_json_full = parsed_json_full
        .to_packet(&item.registry, DEFAULT_MAX_LAYERS)
        .unwrap_or_else(|e| panic!("[{}] {} to_packet full json: {e}", item.corpus, item.name));
    let built_json_full = builder
        .build(
            pkt_json_full,
            Context::default(),
            Options {
                mode: Mode::Permissive,
                ..Options::default()
            },
        )
        .unwrap_or_else(|e| {
            panic!(
                "[{}] {} permissive build full json: {e}",
                item.corpus, item.name
            )
        });
    assert_eq!(
        built_json_full.bytes,
        item.frame.bytes(),
        "[{}] {} full json permissive bytes mismatch",
        item.corpus,
        item.name
    );
}

fn assert_mutated_frame_round_trip(item: &CorpusFrame) {
    if KNOWN_FAILURES.iter().any(|k| k.starts_with(&item.name)) {
        return;
    }

    let dissector = Dissector::new(Arc::clone(&item.registry));
    let decoded = dissector
        .decode(item.frame.clone(), DecodeOptions::default())
        .unwrap_or_else(|e| panic!("[{}] {} decode failed: {e}", item.corpus, item.name));

    let builder = Builder::new(Arc::clone(&item.registry));

    // Minimized document from mutated frame
    let (doc_minimized, _) = Document::from_decoded(&decoded, &item.registry, false);
    let yaml_min = doc_minimized
        .to_yaml_string()
        .unwrap_or_else(|e| panic!("[{}] {} to_yaml_string: {e}", item.corpus, item.name));
    let parsed_yaml = Document::parse(&yaml_min, Format::Yaml, DEFAULT_MAX_DOCUMENT_BYTES)
        .unwrap_or_else(|e| {
            panic!(
                "[{}] {} parse yaml: {e}\nYAML:\n{yaml_min}",
                item.corpus, item.name
            )
        });
    let pkt_yaml = parsed_yaml
        .to_packet(&item.registry, DEFAULT_MAX_LAYERS)
        .unwrap_or_else(|e| panic!("[{}] {} to_packet yaml: {e}", item.corpus, item.name));
    let built_yaml = builder
        .build(
            pkt_yaml,
            Context::default(),
            Options {
                mode: Mode::Permissive,
                ..Options::default()
            },
        )
        .unwrap_or_else(|e| panic!("[{}] {} permissive build yaml: {e}", item.corpus, item.name));
    assert_eq!(
        built_yaml.bytes,
        item.frame.bytes(),
        "[{}] {} mutated yaml permissive bytes mismatch",
        item.corpus,
        item.name
    );

    let json_min = doc_minimized
        .to_json_string()
        .unwrap_or_else(|e| panic!("[{}] {} to_json_string: {e}", item.corpus, item.name));
    let parsed_json = Document::parse(&json_min, Format::Json, DEFAULT_MAX_DOCUMENT_BYTES)
        .unwrap_or_else(|e| panic!("[{}] {} parse json: {e}", item.corpus, item.name));
    let pkt_json = parsed_json
        .to_packet(&item.registry, DEFAULT_MAX_LAYERS)
        .unwrap_or_else(|e| panic!("[{}] {} to_packet json: {e}", item.corpus, item.name));
    let built_json = builder
        .build(
            pkt_json,
            Context::default(),
            Options {
                mode: Mode::Permissive,
                ..Options::default()
            },
        )
        .unwrap_or_else(|e| panic!("[{}] {} permissive build json: {e}", item.corpus, item.name));
    assert_eq!(
        built_json.bytes,
        item.frame.bytes(),
        "[{}] {} mutated json permissive bytes mismatch",
        item.corpus,
        item.name
    );
}

#[test]
fn summary_corpus_counts_and_non_empty() {
    let corpus_1 = load_builtin_defaults_corpus();
    let corpus_2 = load_captures_corpus();
    let corpus_3 = load_protocol_end_to_end_corpus();

    assert!(
        !corpus_1.is_empty(),
        "corpus 1 (builtin defaults) must not be empty"
    );
    assert!(
        !corpus_2.is_empty(),
        "corpus 2 (captures) must not be empty"
    );
    assert!(
        !corpus_3.is_empty(),
        "corpus 3 (protocol end-to-end) must not be empty"
    );

    let mut base_frames = Vec::new();
    base_frames.extend_from_slice(&corpus_1);
    base_frames.extend_from_slice(&corpus_2);
    base_frames.extend_from_slice(&corpus_3);

    for (i, f) in base_frames.iter().enumerate() {
        if f.frame.bytes().is_empty() {
            println!("Empty frame #{i}: [{}] {}", f.corpus, f.name);
        }
    }

    let corpus_4 = generate_mutations(&base_frames);
    assert!(
        !corpus_4.is_empty(),
        "corpus 4 (seeded mutations) must not be empty"
    );

    assert_eq!(corpus_4.len(), base_frames.len() * 8);

    println!(
        "Corpus counts: builtin_defaults={}, captures={}, protocol_end_to_end={}, seeded_mutations={}, total_base={}",
        corpus_1.len(),
        corpus_2.len(),
        corpus_3.len(),
        corpus_4.len(),
        base_frames.len(),
    );
}

#[test]
fn corpus_1_builtin_defaults_round_trip() {
    let corpus = load_builtin_defaults_corpus();
    for item in &corpus {
        assert_frame_round_trip(item);
    }
}

#[test]
fn corpus_2_captures_round_trip() {
    let corpus = load_captures_corpus();
    for item in &corpus {
        assert_frame_round_trip(item);
    }
}

#[test]
fn corpus_3_protocol_end_to_end_fixtures_round_trip() {
    let corpus = load_protocol_end_to_end_corpus();
    for item in &corpus {
        assert_frame_round_trip(item);
    }
}

#[test]
fn corpus_4_seeded_mutations_round_trip() {
    let mut base_frames = Vec::new();
    base_frames.extend(load_builtin_defaults_corpus());
    base_frames.extend(load_captures_corpus());
    base_frames.extend(load_protocol_end_to_end_corpus());

    let mutated_frames = generate_mutations(&base_frames);
    for item in &mutated_frames {
        assert_mutated_frame_round_trip(item);
    }
}
