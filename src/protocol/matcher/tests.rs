// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::any::Any;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use bytes::Bytes;

use crate::packet::{
    Packet,
    field::{FieldKind, FieldValue, WireValue},
    layer::{FieldError, FieldSchema, Layer, LayerSchema, ProtocolId, Raw},
    semantics::BuiltinProtocol,
};
use crate::protocol::{
    icmp::{Icmpv4, Icmpv6},
    network::{Ipv4, Ipv6},
    transport::{Sctp, Tcp, Udp},
};

pub(super) fn echo(source: Ipv4Addr, destination: Ipv4Addr, icmp_type: u8) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source,
            destination,
            ..Ipv4::default()
        })
        .push(Icmpv4 {
            icmp_type,
            body: Bytes::from_static(&[0x12, 0x34, 0, 7]),
            ..Icmpv4::default()
        });
    packet
}

#[derive(Clone, Debug)]
struct ReflectiveUdp {
    source_port: Option<FieldValue>,
    destination_port: Option<FieldValue>,
}

impl Layer for ReflectiveUdp {
    fn schema(&self) -> &'static LayerSchema {
        static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
        static FIELDS: &[FieldSchema] = &[
            FieldSchema {
                name: "source_port",
                kind: FieldKind::Unsigned,
                derived: false,
                required: false,
                description: "test source port",
            },
            FieldSchema {
                name: "destination_port",
                kind: FieldKind::Unsigned,
                derived: false,
                required: false,
                description: "test destination port",
            },
        ];
        SCHEMA.get_or_init(|| LayerSchema {
            protocol: ProtocolId::new(BuiltinProtocol::Udp.as_str()),
            name: "Reflective UDP test layer",
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
        match name {
            "source_port" => self.source_port.clone(),
            "destination_port" => self.destination_port.clone(),
            _ => None,
        }
    }

    fn set_field(&mut self, name: &str, _value: FieldValue) -> Result<(), FieldError> {
        Err(FieldError::UnknownField {
            protocol: self.protocol_id(),
            field: name.to_owned(),
        })
    }
}

#[derive(Clone, Debug)]
pub(super) struct MalformedIpv4;

impl Layer for MalformedIpv4 {
    fn schema(&self) -> &'static LayerSchema {
        static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
        static FIELDS: &[FieldSchema] = &[
            FieldSchema {
                name: "source",
                kind: FieldKind::Ipv4,
                derived: false,
                required: true,
                description: "test source",
            },
            FieldSchema {
                name: "destination",
                kind: FieldKind::Ipv4,
                derived: false,
                required: true,
                description: "test destination",
            },
        ];
        SCHEMA.get_or_init(|| LayerSchema {
            protocol: ProtocolId::new(BuiltinProtocol::Ipv4.as_str()),
            name: "Malformed IPv4 test layer",
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
        matches!(name, "source" | "destination")
            .then(|| FieldValue::Text("not-an-address".to_owned()))
    }

    fn set_field(&mut self, name: &str, _value: FieldValue) -> Result<(), FieldError> {
        Err(FieldError::UnknownField {
            protocol: self.protocol_id(),
            field: name.to_owned(),
        })
    }
}

pub(super) fn reflective_udp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: Option<FieldValue>,
    destination_port: Option<FieldValue>,
) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source,
            destination,
            ..Ipv4::default()
        })
        .push(ReflectiveUdp {
            source_port,
            destination_port,
        });
    packet
}

fn init_chunk(chunk_type: u8, initiate_tag: u32) -> Vec<u8> {
    let mut chunk = vec![chunk_type, 0, 0, 20];
    chunk.extend_from_slice(&initiate_tag.to_be_bytes());
    chunk.extend_from_slice(&65_535_u32.to_be_bytes());
    chunk.extend_from_slice(&1_u16.to_be_bytes());
    chunk.extend_from_slice(&1_u16.to_be_bytes());
    chunk.extend_from_slice(&0_u32.to_be_bytes());
    chunk
}

pub(super) fn sctp_init(source: Ipv4Addr, destination: Ipv4Addr, initiate_tag: u32) -> Packet {
    let chunk = init_chunk(1, initiate_tag);
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source,
            destination,
            ..Ipv4::default()
        })
        .push(Sctp {
            source_port: 40_000,
            destination_port: 5_000,
            verification_tag: 0,
            checksum: WireValue::Exact(initiate_tag.rotate_left(7)),
        })
        .push(Raw::new(chunk));
    packet
}

pub(super) fn sctp_init_ack(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    verification_tag: u32,
    initiate_tag: u32,
) -> Packet {
    let mut packet = sctp_init(source, destination, initiate_tag);
    let sctp = packet.get_mut::<Sctp>().unwrap();
    sctp.source_port = 5_000;
    sctp.destination_port = 40_000;
    sctp.verification_tag = verification_tag;
    let raw = packet.get_mut::<Raw>().unwrap();
    raw.bytes = Bytes::from(init_chunk(2, initiate_tag));
    packet
}

pub(super) fn quoted_icmpv4_time_exceeded(
    router: Ipv4Addr,
    source: Ipv4Addr,
    protocol: u8,
    request: &Packet,
) -> Packet {
    let request_network = request.get::<Ipv4>().unwrap();
    let quote_length = if protocol == 132 { 40 } else { 28 };
    let mut quote = vec![0_u8; quote_length];
    quote[0] = 0x45;
    quote[2..4].copy_from_slice(&u16::try_from(quote_length).unwrap().to_be_bytes());
    quote[9] = protocol;
    quote[12..16].copy_from_slice(&request_network.source.octets());
    quote[16..20].copy_from_slice(&request_network.destination.octets());
    match protocol {
        6 => {
            let tcp = request.get::<Tcp>().unwrap();
            quote[20..22].copy_from_slice(&tcp.source_port.to_be_bytes());
            quote[22..24].copy_from_slice(&tcp.destination_port.to_be_bytes());
            quote[24..28].copy_from_slice(&tcp.sequence.to_be_bytes());
        }
        17 => {
            let udp = request.get::<Udp>().unwrap();
            quote[20..22].copy_from_slice(&udp.source_port.to_be_bytes());
            quote[22..24].copy_from_slice(&udp.destination_port.to_be_bytes());
        }
        132 => {
            let sctp = request.get::<Sctp>().unwrap();
            quote[20..22].copy_from_slice(&sctp.source_port.to_be_bytes());
            quote[22..24].copy_from_slice(&sctp.destination_port.to_be_bytes());
            quote[24..28].copy_from_slice(&sctp.verification_tag.to_be_bytes());
            let checksum = match &sctp.checksum {
                WireValue::Exact(checksum) => checksum.to_le_bytes(),
                WireValue::Raw(checksum) => checksum.as_ref().try_into().unwrap(),
                WireValue::Auto => panic!("SCTP matcher fixture checksum must be materialized"),
            };
            quote[28..32].copy_from_slice(&checksum);
            let chunk = &request.get::<Raw>().unwrap().bytes;
            quote[32..40].copy_from_slice(&chunk[..8]);
        }
        1 => {
            let icmp = request.get::<Icmpv4>().unwrap();
            quote[20] = icmp.icmp_type;
            quote[21] = icmp.code;
            quote[24..28].copy_from_slice(&icmp.body[..4]);
        }
        _ => unreachable!("test only covers registered IPv4 probe transports"),
    }
    let mut body = vec![0_u8; 4];
    body.extend(quote);
    let mut response = Packet::new();
    response
        .push(Ipv4 {
            source: router,
            destination: source,
            ..Ipv4::default()
        })
        .push(Icmpv4 {
            icmp_type: 11,
            body: body.into(),
            ..Icmpv4::default()
        });
    response
}

pub(super) fn quoted_icmpv6_time_exceeded(
    router: Ipv6Addr,
    source: Ipv6Addr,
    request: &Packet,
) -> Packet {
    let request_network = request.get::<Ipv6>().unwrap();
    let udp = request.get::<Udp>().unwrap();
    let mut quote = vec![0_u8; 48];
    quote[0] = 0x60;
    quote[4..6].copy_from_slice(&8_u16.to_be_bytes());
    quote[6] = 17;
    quote[8..24].copy_from_slice(&request_network.source.octets());
    quote[24..40].copy_from_slice(&request_network.destination.octets());
    quote[40..42].copy_from_slice(&udp.source_port.to_be_bytes());
    quote[42..44].copy_from_slice(&udp.destination_port.to_be_bytes());
    let mut body = vec![0_u8; 4];
    body.extend(quote);
    let mut response = Packet::new();
    response
        .push(Ipv6 {
            source: router,
            destination: source,
            ..Ipv6::default()
        })
        .push(Icmpv6 {
            icmp_type: 3,
            body: body.into(),
            ..Icmpv6::default()
        });
    response
}

pub(super) fn address(value: &str) -> Ipv6Addr {
    value.parse().unwrap()
}

pub(super) fn tcp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    sequence: u32,
    acknowledgment: u32,
    flags: u16,
) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source,
            destination,
            ..Ipv4::default()
        })
        .push(Tcp {
            source_port: if source.octets()[3] == 1 { 40_000 } else { 443 },
            destination_port: if source.octets()[3] == 1 { 443 } else { 40_000 },
            sequence,
            acknowledgment,
            flags,
            ..Tcp::default()
        });
    packet
}
