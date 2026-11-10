// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use crate::codec::Addresses;
use crate::protocol::BuiltinProtocol;
use crate::protocol::headers::{IpHeader, LinkHeader};
use crate::protocol::network::{Ipv4, Ipv6};

#[test]
fn catalog_capabilities_come_from_their_own_facts() {
    use BuiltinProtocol::{Dns, Dtls, Ethernet, Http, Ipv4, Mpls, Mqtt, Raw, Tcp, Tls, Udp};
    assert!(Dtls.is_message_protocol());
    assert!(!Dns.is_message_protocol());
    assert!(Mqtt.stream_decode());
    assert!(!Dns.stream_decode());
    assert!(!Http.stream_decode());
    assert!(!Tls.stream_decode());
    assert!(Dns.supports_transport(Tcp));
    assert!(Dns.supports_transport(Udp));
    assert!(Tls.supports_transport(Tcp));
    assert!(Mpls.supports_transport(Udp));
    assert!(!Http.supports_transport(Udp));
    assert!(!Udp.supports_transport(Tcp));
    assert!(!Dns.supports_transport(Ipv4));
    assert!(!Raw.supports_transport(Ethernet));
    let registry = super::registry();
    for protocol in BuiltinProtocol::ALL {
        for (parent, ports) in [
            (Tcp.as_str(), protocol.tcp_ports()),
            (Udp.as_str(), protocol.udp_ports()),
        ] {
            for &port in ports {
                assert_eq!(
                    registry
                        .child_for(parent, crate::registry::Discriminator(u64::from(port)))
                        .map(crate::layer::Id::as_str),
                    Some(protocol.as_str()),
                    "{parent} port {port} should dissect as {}",
                    protocol.as_str()
                );
            }
        }
    }
}

#[test]
fn filter_field_bindings_read_their_declared_fields() {
    use crate::protocol::link::Ethernet;
    use crate::protocol::network::Ipv4;
    use crate::protocol::transport::Tcp;

    let registry = super::registry();
    let mut packet = crate::packet::Packet::default();
    packet.push(Ethernet::default());
    packet.push(Ipv4 {
        source: "192.0.2.1".parse().unwrap(),
        destination: "192.0.2.2".parse().unwrap(),
        ..Default::default()
    });
    packet.push(Tcp {
        source_port: 40000,
        destination_port: 1883,
        ..Default::default()
    });
    let built = crate::build::Builder::new(registry.clone())
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    let decoded = crate::decode::Dissector::new(registry.clone())
        .decode(
            crate::frame::Frame::new(None, crate::frame::LinkType::ETHERNET, built.bytes).unwrap(),
            Default::default(),
        )
        .unwrap();
    let context = crate::filter::Context::frame(&decoded, 1);
    for (source, expected) in [
        ("ip.src == 192.0.2.1", true),
        ("ip.dst == 192.0.2.2", true),
        ("tcp.srcport == 40000", true),
        ("tcp.dstport == 1883", true),
        ("tcp.srcport == 1883", false),
        ("tcp.dstport == 40000", false),
    ] {
        let filter = crate::filter::Filter::compile(source, &registry, Default::default())
            .unwrap_or_else(|error| panic!("{source}: {error}"));
        assert_eq!(filter.matches(&context).unwrap(), expected, "{source}");
    }
}

#[test]
fn filter_field_bindings_reject_incompatible_literals() {
    let registry = super::registry();
    let error =
        crate::filter::Filter::compile("tcp.srcport == \"hello\"", &registry, Default::default())
            .expect_err("a port cannot compare to text");
    assert!(
        matches!(error, crate::filter::Error::IncompatibleLiteral { .. }),
        "{error:?}"
    );
}

#[test]
fn catalog_codec_and_schema_ids_agree() {
    let registry = super::registry();
    for protocol in BuiltinProtocol::ALL {
        let name = protocol.as_str();
        let codec = registry
            .codec(name)
            .unwrap_or_else(|| panic!("{name}: catalog protocol has no registered codec"));
        assert_eq!(*codec.protocol_id(), protocol.id(), "{name}");
        assert_eq!(registry.protocol_named(name), Some(protocol.id()), "{name}");
        for alias in protocol.aliases() {
            assert_eq!(
                registry.protocol_named(alias),
                Some(protocol.id()),
                "{name}: alias {alias}"
            );
        }
        assert_eq!(
            registry.matcher(name).is_some(),
            protocol.has_matcher(),
            "{name}: matcher registration disagrees with the catalog"
        );
        if *protocol == BuiltinProtocol::RawIp {
            assert!(codec.schema().is_none(), "{name}");
            assert!(codec.new_layer().is_err(), "{name}");
            continue;
        }
        let schema = codec
            .schema()
            .unwrap_or_else(|| panic!("{name}: codec declares no schema"));
        assert_eq!(schema.protocol, protocol.id(), "{name}");
        assert_eq!(registry.schema(name), Some(schema), "{name}");
        if protocol.is_constructible() {
            let layer = codec
                .new_layer()
                .unwrap_or_else(|error| panic!("{name}: new_layer failed: {error}"));
            assert_eq!(*layer.protocol_id(), protocol.id(), "{name}");
            assert_eq!(layer.schema().protocol, protocol.id(), "{name}");
            assert!(
                protocol.identifies(layer.as_ref()),
                "{name}: default layer is not the catalog layer type"
            );
        }
    }
    for registered in registry.protocols() {
        assert!(
            BuiltinProtocol::from_id(*registered).is_some(),
            "{registered}: registered codec has no catalog row"
        );
    }
}

#[test]
fn packet_documents_round_trip_through_build() {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../examples/captures/protocols.manifest.json"
    ))
    .unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let entries = manifest["protocols"].as_array().unwrap();
    let mut checked = 0_usize;
    for entry in entries {
        let name = entry["protocol"].as_str().unwrap();
        let document_path = entry["packet_document"]
            .as_str()
            .unwrap_or_else(|| panic!("{name}: manifest entry has no packet document"));
        let registry = Arc::new(
            super::registry_with(|builder| {
                if let Some(binding) = entry["decode_as"].as_str() {
                    let (selector, child) = binding.split_once(':').unwrap();
                    let port = selector.split_once('=').unwrap().1.parse::<u64>().unwrap();
                    builder.replace_binding(
                        "udp",
                        port,
                        BuiltinProtocol::from_name(child).unwrap().as_str(),
                        crate::registry::Priority::Primary,
                    )?;
                }
                Ok(())
            })
            .unwrap(),
        );
        let text = std::fs::read_to_string(root.join(document_path)).unwrap();
        let document =
            crate::document::Packet::parse(&text, crate::document::Format::Json, text.len())
                .unwrap_or_else(|error| panic!("{name}: parse: {error}"));
        let packet = document
            .to_packet(&registry, 64)
            .unwrap_or_else(|error| panic!("{name}: to_packet: {error}"));
        let built = crate::build::Builder::new(registry.clone())
            .build(packet, Addresses::default(), Default::default())
            .unwrap_or_else(|error| panic!("{name}: build: {error}"));
        let capture = std::fs::read(
            root.join("examples/captures")
                .join(entry["capture"].as_str().unwrap()),
        )
        .unwrap();
        let mut reader =
            crate::capture_file::Reader::with_limits(&capture[..], Default::default()).unwrap();
        let frame = reader.next_frame().unwrap().unwrap();
        assert_eq!(built.bytes, frame.bytes().clone(), "{name}");
        let redocumented = crate::document::Packet::from_packet(&built.packet);
        let repacket = redocumented
            .to_packet(&registry, 64)
            .unwrap_or_else(|error| panic!("{name}: second to_packet: {error}"));
        let rebuilt = crate::build::Builder::new(registry)
            .build(repacket, Addresses::default(), Default::default())
            .unwrap_or_else(|error| panic!("{name}: rebuild: {error}"));
        assert_eq!(rebuilt.bytes, built.bytes, "{name}");
        checked += 1;
    }
    assert_eq!(checked, entries.len());
}

#[test]
fn yaml_packet_document_builds() {
    let text = include_str!("../../../../../examples/documents/packet-raw.yaml");
    let document = crate::document::Packet::parse(text, crate::document::Format::Yaml, text.len())
        .expect("yaml packet document parses");
    let registry = super::registry();
    let packet = document
        .to_packet(&registry, 64)
        .expect("yaml packet document converts");
    let built = crate::build::Builder::new(registry)
        .build(packet, Addresses::default(), Default::default())
        .expect("yaml packet document builds");
    assert_eq!(built.bytes.as_ref(), &[222, 173, 190, 239][..]);
}

#[test]
fn headers_match_capture_decoding() {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../examples/captures/protocols.manifest.json"
    ))
    .unwrap();
    let registry = super::registry();
    let mut checked = 0_usize;
    for entry in manifest["protocols"].as_array().unwrap() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/captures")
            .join(entry["capture"].as_str().unwrap());
        let capture = std::fs::read(&path).unwrap();
        let mut reader =
            crate::capture_file::Reader::with_limits(&capture[..], Default::default()).unwrap();
        while let Some(frame) = reader.next_frame().unwrap() {
            let bytes = frame.bytes().clone();
            let Ok(Some(link)) = LinkHeader::walk(frame.link_type, &bytes) else {
                continue;
            };
            let Ok(Some(ip)) = link.walk_ip(&bytes) else {
                continue;
            };
            let decoded = crate::decode::Dissector::new(registry.clone())
                .decode(frame, Default::default())
                .unwrap();
            let ip_index = decoded
                .packet
                .iter()
                .position(|layer| BuiltinProtocol::of(layer).is_some_and(BuiltinProtocol::is_ip));
            let Some(ip_index) = ip_index else {
                continue;
            };
            let layout = decoded.layout.layer(ip_index).unwrap();
            assert_eq!(
                link.network_offset(),
                layout.range.start,
                "{}: network offset",
                entry["protocol"]
            );
            let (source, destination) = ip.addresses(&bytes[layout.range.start..]).unwrap();
            let layer = decoded.packet.layer(ip_index).unwrap();
            match &ip {
                IpHeader::V4(header) => {
                    let layer = layer.downcast_ref::<Ipv4>().unwrap();
                    assert_eq!(source, std::net::IpAddr::from(layer.source));
                    assert_eq!(destination, std::net::IpAddr::from(layer.destination));
                    assert_eq!(
                        header.header_length(),
                        layout.range.end - layout.range.start
                    );
                    if let Some(payload) = decoded.packet.encoded_payload_length(ip_index) {
                        assert_eq!(header.total_length(), header.header_length() + payload);
                    }
                }
                IpHeader::V6(header) => {
                    let layer = layer.downcast_ref::<Ipv6>().unwrap();
                    assert_eq!(source, std::net::IpAddr::from(layer.source));
                    assert_eq!(destination, std::net::IpAddr::from(layer.destination));
                    let decoded_extensions = decoded
                        .packet
                        .iter()
                        .skip(ip_index + 1)
                        .take_while(|candidate| {
                            BuiltinProtocol::of(*candidate).is_some_and(|protocol| {
                                protocol.is_ipv6_extension()
                                    || protocol == BuiltinProtocol::Ipv6Fragment
                            })
                        })
                        .count();
                    assert_eq!(
                        header.extensions().len(),
                        decoded_extensions,
                        "{}: extension count",
                        entry["protocol"]
                    );
                    for (offset, extension) in header.extensions().iter().enumerate() {
                        let extension_layout = decoded.layout.layer(ip_index + 1 + offset).unwrap();
                        assert_eq!(
                            extension.range().start + layout.range.start,
                            extension_layout.range.start,
                            "{}: extension {offset} start",
                            entry["protocol"]
                        );
                        assert_eq!(
                            extension.range().end + layout.range.start,
                            extension_layout.range.end,
                            "{}: extension {offset} end",
                            entry["protocol"]
                        );
                    }
                }
            }
            checked += 1;
        }
    }
    assert!(checked >= 30, "only {checked} captures compared");
    let _ = Arc::clone(&registry);
}

#[test]
fn layout_indices_and_ranges_are_valid() {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../examples/captures/protocols.manifest.json"
    ))
    .unwrap();
    let registry = super::registry();
    let check = |layout: &crate::layout::PacketLayout, packet: &crate::packet::Packet| {
        for layer_layout in &layout.layers {
            let layer = packet.layer(layer_layout.index).unwrap();
            assert_eq!(layer_layout.schema, layer.schema());
            for field in &layer_layout.fields {
                assert!(
                    field.index < layer_layout.schema.fields.len(),
                    "{}: layout index {} does not resolve",
                    layer_layout.protocol,
                    field.index
                );
            }
        }
    };
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for entry in manifest["protocols"].as_array().unwrap() {
        let registry_with = Arc::new(
            super::registry_with(|builder| {
                if let Some(binding) = entry["decode_as"].as_str() {
                    let (selector, child) = binding.split_once(':').unwrap();
                    let port = selector.split_once('=').unwrap().1.parse::<u64>().unwrap();
                    builder.replace_binding(
                        "udp",
                        port,
                        BuiltinProtocol::from_name(child).unwrap().as_str(),
                        crate::registry::Priority::Primary,
                    )?;
                }
                Ok(())
            })
            .unwrap(),
        );
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/captures")
            .join(entry["capture"].as_str().unwrap());
        let capture = std::fs::read(&path).unwrap();
        let mut reader =
            crate::capture_file::Reader::with_limits(&capture[..], Default::default()).unwrap();
        while let Some(frame) = reader.next_frame().unwrap() {
            let decoded = crate::decode::Dissector::new(registry.clone())
                .decode(frame, Default::default())
                .unwrap();
            check(&decoded.layout, &decoded.packet);
            for layer_layout in &decoded.layout.layers {
                for field in &layer_layout.fields {
                    assert!(
                        field.range.start >= layer_layout.range.start
                            && field.range.end <= layer_layout.range.end,
                        "{}: field range escapes its layer",
                        entry["protocol"]
                    );
                }
            }
        }
        if let Some(document_path) = entry["packet_document"].as_str() {
            let text = std::fs::read_to_string(root.join(document_path)).unwrap();
            let document =
                crate::document::Packet::parse(&text, crate::document::Format::Json, text.len())
                    .unwrap();
            let packet = document.to_packet(&registry_with, 64).unwrap();
            let built = crate::build::Builder::new(registry_with)
                .build(packet, Addresses::default(), Default::default())
                .unwrap();
            check(&built.layout, &built.packet);
        }
    }
}

#[test]
fn every_example_capture_decodes() {
    let registry = super::registry();
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/captures");
    let mut files: Vec<_> = std::fs::read_dir(&directory)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext == "pcap" || ext == "pcapng")
        })
        .collect();
    files.sort();
    assert!(files.len() >= 48, "{}", files.len());
    for path in files {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let capture = std::fs::read(&path).unwrap();
        let mut reader = crate::capture_file::Reader::with_limits(&capture[..], Default::default())
            .unwrap_or_else(|error| panic!("{name}: open: {error}"));
        let mut frames = 0_usize;
        while let Some(frame) = reader
            .next_frame()
            .unwrap_or_else(|error| panic!("{name}: frame: {error}"))
        {
            crate::decode::Dissector::new(registry.clone())
                .decode(frame, Default::default())
                .unwrap_or_else(|error| panic!("{name}: decode: {error}"));
            frames += 1;
        }
        assert!(frames > 0, "{name}: no frames");
    }
}
