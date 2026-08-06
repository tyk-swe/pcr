// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::any::Any;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use super::destination::{ROUTE_FIELDS, live_destinations};
use super::path::{
    DESTINATION, DESTINATION_PORT, IPV4_OPTIONS, SEGMENTS, SOURCE, outer_ip_path, outer_scope_len,
};
use crate::field::FieldValue;
use crate::layer::{FieldError, FieldSchema, Layer, LayerSchema, ProtocolId};
use crate::model::Packet;
use crate::semantics::BuiltinProtocol;

#[derive(Clone, Debug)]
struct RuntimeFieldLayer {
    field: &'static str,
}

impl Layer for RuntimeFieldLayer {
    fn schema(&self) -> &'static LayerSchema {
        static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
        static FIELDS: &[FieldSchema] = &[];
        SCHEMA.get_or_init(|| LayerSchema {
            protocol: ProtocolId::new("test.runtime_fields"),
            name: "Runtime field test layer",
            fields: FIELDS,
        })
    }

    fn clone_box(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn field(&self, name: &str) -> Option<FieldValue> {
        (name == self.field).then(|| match name {
            SEGMENTS => FieldValue::List(Vec::new()),
            DESTINATION_PORT => FieldValue::Unsigned(9),
            _ => FieldValue::Ipv4(Ipv4Addr::LOCALHOST),
        })
    }

    fn set_field(&mut self, name: &str, _value: FieldValue) -> Result<(), FieldError> {
        Err(FieldError::UnknownField {
            protocol: self.protocol_id().clone(),
            field: name.to_owned(),
        })
    }
}

#[test]
fn built_in_identity_is_canonical_and_does_not_accept_runtime_aliases() {
    let mut spellings = BTreeMap::new();
    for protocol in BuiltinProtocol::ALL {
        let canonical = protocol.as_str();
        assert_eq!(BuiltinProtocol::from_name(canonical), Some(*protocol));
        assert_eq!(
            BuiltinProtocol::from_id(&ProtocolId::new(canonical)),
            Some(*protocol)
        );
        assert_eq!(
            BuiltinProtocol::from_name_or_alias(canonical),
            Some(*protocol)
        );
        assert_eq!(spellings.insert(canonical, *protocol), None);

        for alias in protocol.aliases() {
            assert_eq!(BuiltinProtocol::from_name(alias), None);
            assert_eq!(BuiltinProtocol::from_id(&ProtocolId::new(*alias)), None);
            assert_eq!(BuiltinProtocol::from_name_or_alias(alias), Some(*protocol));
            assert_eq!(
                spellings.insert(alias, *protocol),
                None,
                "duplicate built-in protocol spelling {alias}"
            );
        }
    }
    assert_eq!(BuiltinProtocol::ALL.len(), 37);
    assert_eq!(
        BuiltinProtocol::from_id(&ProtocolId::new("raw_ip")),
        Some(BuiltinProtocol::RawIp)
    );
    assert_eq!(BuiltinProtocol::from_id(&ProtocolId::new("ip")), None);
    assert_eq!(BuiltinProtocol::from_id(&ProtocolId::new("srh")), None);
}

#[derive(Clone, Debug)]
struct StackLayer {
    schema: &'static LayerSchema,
    source: Option<IpAddr>,
    destination: Option<IpAddr>,
    fragment_offset: Option<u64>,
    more_fragments: Option<bool>,
    next_header: Option<u64>,
}

fn stack_layer(protocol: &'static str) -> StackLayer {
    StackLayer {
        // Leaking one tiny schema per pushed layer keeps this test free
        // of protocol-crate codecs while satisfying the 'static schema
        // contract.
        schema: Box::leak(Box::new(LayerSchema {
            protocol: ProtocolId::new(protocol),
            name: "Semantics stack test layer",
            fields: &[],
        })),
        source: None,
        destination: None,
        fragment_offset: None,
        more_fragments: None,
        next_header: None,
    }
}

fn stack_ip_layer(source: Ipv4Addr, destination: Ipv4Addr) -> StackLayer {
    StackLayer {
        source: Some(IpAddr::V4(source)),
        destination: Some(IpAddr::V4(destination)),
        ..stack_layer("ipv4")
    }
}

impl Layer for StackLayer {
    fn schema(&self) -> &'static LayerSchema {
        self.schema
    }

    fn clone_box(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn field(&self, name: &str) -> Option<FieldValue> {
        match name {
            SOURCE => self.source.map(ip_field_value),
            DESTINATION => self.destination.map(ip_field_value),
            IPV4_OPTIONS => None,
            "fragment_offset" => self.fragment_offset.map(FieldValue::Unsigned),
            "more_fragments" => self.more_fragments.map(FieldValue::Bool),
            "next_header" => self.next_header.map(FieldValue::Unsigned),
            _ => None,
        }
    }

    fn set_field(&mut self, name: &str, _value: FieldValue) -> Result<(), FieldError> {
        Err(FieldError::UnknownField {
            protocol: self.protocol_id().clone(),
            field: name.to_owned(),
        })
    }
}

fn ip_field_value(value: IpAddr) -> FieldValue {
    match value {
        IpAddr::V4(value) => FieldValue::Ipv4(value),
        IpAddr::V6(value) => FieldValue::Ipv6(value),
    }
}

#[test]
fn the_outer_scope_ends_at_the_first_encapsulation_boundary() {
    let outer_destination = Ipv4Addr::new(10, 0, 0, 2);
    let mut tunneled = Packet::new();
    tunneled
        .push(stack_layer("ethernet"))
        .push(stack_ip_layer(
            Ipv4Addr::new(10, 0, 0, 1),
            outer_destination,
        ))
        .push(stack_layer("udp"))
        .push(stack_layer("vxlan"))
        .push(stack_layer("ethernet"))
        .push(stack_ip_layer(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 5),
        ));

    assert_eq!(outer_scope_len(&tunneled), 4);
    let path = outer_ip_path(&tunneled).unwrap().unwrap();
    assert_eq!(path.header_destination, IpAddr::V4(outer_destination));

    let mut plain = Packet::new();
    plain.push(stack_layer("ethernet")).push(stack_ip_layer(
        Ipv4Addr::new(10, 0, 0, 1),
        outer_destination,
    ));
    assert_eq!(outer_scope_len(&plain), plain.len());

    let mut gre = Packet::new();
    gre.push(stack_layer("ethernet"))
        .push(stack_ip_layer(
            Ipv4Addr::new(10, 0, 0, 1),
            outer_destination,
        ))
        .push(stack_layer("gre"))
        .push(stack_layer("ethernet"))
        .push(stack_ip_layer(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 5),
        ));
    assert_eq!(outer_scope_len(&gre), 3);
    assert_eq!(
        outer_ip_path(&gre).unwrap().unwrap().header_destination,
        IpAddr::V4(outer_destination)
    );
}

#[test]
fn a_tunneled_ip_header_is_not_an_outer_path() {
    let mut packet = Packet::new();
    packet
        .push(stack_layer("vxlan"))
        .push(stack_layer("ethernet"))
        .push(stack_ip_layer(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 5),
        ));

    assert_eq!(outer_scope_len(&packet), 1);
    assert_eq!(outer_ip_path(&packet).unwrap(), None);
}

#[test]
fn unknown_runtime_route_fields_fail_closed_but_destination_port_does_not() {
    for field in ROUTE_FIELDS {
        let mut packet = Packet::new();
        packet.push(RuntimeFieldLayer { field });
        let error = live_destinations(&packet).unwrap_err();
        assert!(error.to_string().contains(field));
    }

    let mut packet = Packet::new();
    packet.push(RuntimeFieldLayer {
        field: DESTINATION_PORT,
    });
    assert_eq!(live_destinations(&packet).unwrap(), Vec::<IpAddr>::new());
}

#[test]
fn malformed_route_layers_fail_closed() {
    for protocol in [
        "ethernet", "raw_ip", "ipv4", "ipv6_srh", "udp", "gre", "vxlan", "geneve", "mpls", "ppp",
    ] {
        let mut packet = Packet::new();
        packet.push(crate::layer::MalformedLayer::new(
            Some(ProtocolId::new(protocol)),
            Vec::<u8>::new(),
            "truncated",
        ));
        assert!(live_destinations(&packet).is_err(), "{protocol}");
    }

    let mut alias = Packet::new();
    alias.push(crate::layer::MalformedLayer::new(
        Some(ProtocolId::new("ip")),
        Vec::<u8>::new(),
        "truncated",
    ));
    assert!(live_destinations(&alias).is_err());

    for protocol in ["raw", "tcp", "icmpv4", "dns"] {
        let mut packet = Packet::new();
        packet.push(crate::layer::MalformedLayer::new(
            Some(ProtocolId::new(protocol)),
            Vec::<u8>::new(),
            "truncated",
        ));
        assert!(live_destinations(&packet).is_ok(), "{protocol}");
    }
}

#[test]
fn non_atomic_ip_fragments_fail_closed_including_type_43() {
    let mut ipv4 = Packet::new();
    let mut ipv4_layer = stack_ip_layer(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST);
    ipv4_layer.more_fragments = Some(true);
    ipv4.push(ipv4_layer);
    assert!(live_destinations(&ipv4).is_err());

    let mut ipv6 = Packet::new();
    let mut ipv6_layer = stack_layer("ipv6");
    ipv6_layer.source = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
    ipv6_layer.destination = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
    let mut fragment = stack_layer("ipv6_fragment");
    fragment.fragment_offset = Some(1);
    fragment.next_header = Some(43);
    ipv6.push(ipv6_layer).push(fragment);
    assert!(live_destinations(&ipv6).is_err());
}
