// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use bytes::Bytes;

use crate::{
    codec::{Addresses, DecodeContext, Decoded, EncodeContext, Mode},
    document, field,
    frame::{Frame, LinkType},
    layer::Layer,
    packet::Packet,
    protocol::{
        application::{dtls::Dtls, sflow::Sflow, sip::Sip},
        builtin,
        framing::Framer,
        link::Ethernet,
        network::Ipv4,
        transport::{Tcp, Udp},
    },
};

use super::{Records, record};

fn round_trip(name: &str, wire: &[u8], expected: &[(&str, field::Value)]) {
    round_trip_inner(name, wire, false, expected);
}

fn round_trip_ipv6(name: &str, wire: &[u8], expected: &[(&str, field::Value)]) {
    round_trip_inner(name, wire, true, expected);
}

fn round_trip_inner(name: &str, wire: &[u8], ipv6: bool, expected: &[(&str, field::Value)]) {
    let network = ipv6.then(|| crate::codec::NetworkEnvelope {
        source: "2001:db8::1".parse().unwrap(),
        destination: "2001:db8::2".parse().unwrap(),
    });
    let registry = builtin::registry();
    let codec = registry.codec(name).unwrap();
    let decoded = codec
        .decode(
            Bytes::copy_from_slice(wire),
            &DecodeContext {
                parent: None,
                registry: &registry,
                network,
                hop_limit: None,
                discriminator: None,
            },
        )
        .unwrap();
    assert_eq!(decoded.layer.protocol_id().as_str(), name, "{name}");
    assert_eq!(decoded.consumed, wire.len());
    assert_fields(decoded.layer.as_ref(), expected);
    let mut packet = Packet::new();
    packet.push_boxed(decoded.layer);
    let addresses = network
        .map(|n| Addresses {
            source: Some(n.source),
            destination: Some(n.destination),
        })
        .unwrap_or_default();
    let context = EncodeContext {
        packet: &packet,
        index: 0,
        build_context: &addresses,
        mode: Mode::Strict,
        registry: &registry,
        child: None,
        remaining_packet_bytes: 65536,
    };
    let encoded = codec
        .encode(packet.layer(0).unwrap(), &[], &context)
        .unwrap();
    assert_eq!(encoded.prefix, wire, "{name}");
    let refused = EncodeContext {
        remaining_packet_bytes: wire.len().saturating_sub(1),
        ..context
    };
    assert!(
        codec
            .encode(packet.layer(0).unwrap(), &[], &refused)
            .is_err(),
        "budget {name}"
    );
}

fn preserve_wire(name: &str, wire: &[u8], expected: &[(&str, field::Value)]) {
    let registry = builtin::registry();
    let codec = registry.codec(name).unwrap();
    let decoded = codec
        .decode(
            Bytes::copy_from_slice(wire),
            &DecodeContext {
                parent: None,
                registry: &registry,
                network: None,
                hop_limit: None,
                discriminator: None,
            },
        )
        .unwrap();
    assert_eq!(decoded.layer.protocol_id().as_str(), name);
    assert_eq!(decoded.consumed, wire.len());
    assert_fields(decoded.layer.as_ref(), expected);
    let mut packet = Packet::new();
    packet.push_boxed(decoded.layer);
    let built = crate::build::Builder::new(registry)
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    assert_eq!(built.bytes.as_ref(), wire);
}

fn assert_fields(layer: &dyn Layer, expected: &[(&str, field::Value)]) {
    for (path, value) in expected {
        assert_eq!(
            layer.field_path(&path.parse().unwrap()).as_ref(),
            Some(value),
            "{path}"
        );
    }
}

fn decode(name: &str, wire: &[u8]) -> Result<Decoded, crate::codec::Error> {
    let registry = builtin::registry();
    let decoded = registry.codec(name).unwrap().decode(
        Bytes::copy_from_slice(wire),
        &DecodeContext {
            parent: None,
            registry: &registry,
            network: None,
            hop_limit: None,
            discriminator: None,
        },
    )?;
    if decoded.layer.protocol_id().as_str() != name {
        return Err(crate::protocol::common::invalid(
            "test",
            "unsupported input retained raw",
        ));
    }
    Ok(decoded)
}

fn slice<'a>(name: &str, field: &str, wire: &'a [u8]) -> &'a [u8] {
    let decoded = decode(name, wire).unwrap();
    let range = decoded
        .fields
        .iter()
        .find(|f| f.name == field)
        .unwrap()
        .range;
    &wire[range.start..range.end]
}

mod framing;
mod reference;
mod reflection;
mod validation;
