// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Raw-IP TCP frame builders and an in-memory capture shared by the stateful
//! analysis targets.

use std::io::Cursor;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

use packetcraftr_core::capture_file::{Format, Reader, ReaderLimits, Writer};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::{builtin, checksum_parts};
use packetcraftr_core::registry::Registry;

/// Keeps every TCP segment and IP datagram length within a `u16`.
pub const MAX_SEGMENT_PAYLOAD: usize = 1460;

const TCP: u8 = 6;
const IPV6_FRAGMENT: u8 = 44;

pub fn registry() -> Arc<Registry> {
    static REGISTRY: OnceLock<Arc<Registry>> = OnceLock::new();
    Arc::clone(REGISTRY.get_or_init(builtin::registry))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

impl Direction {
    pub const fn from_bit(server: bool) -> Self {
        if server {
            Self::ServerToClient
        } else {
            Self::ClientToServer
        }
    }

    pub const fn reverse(self) -> Self {
        match self {
            Self::ClientToServer => Self::ServerToClient,
            Self::ServerToClient => Self::ClientToServer,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Ipv4,
    Ipv6,
}

impl Family {
    pub const fn from_bit(ipv6: bool) -> Self {
        if ipv6 { Self::Ipv6 } else { Self::Ipv4 }
    }
}

const IPV4_CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const IPV4_SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
const IPV6_CLIENT: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const IPV6_SERVER: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

#[derive(Clone, Copy, Debug)]
pub struct Conversation {
    pub family: Family,
    pub client_port: u16,
    pub server_port: u16,
}

const fn oriented<T: Copy>(direction: Direction, client: T, server: T) -> (T, T) {
    match direction {
        Direction::ClientToServer => (client, server),
        Direction::ServerToClient => (server, client),
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Segment<'a> {
    pub flags: u8,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub window: u16,
    /// Truncated to [`MAX_SEGMENT_PAYLOAD`].
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug)]
pub struct Fragment {
    /// Offset in 8-byte units; IPv4 keeps the low 13 bits.
    pub offset_units: u16,
    pub more: bool,
}

#[derive(Clone, Copy)]
enum Hosts {
    V4(Ipv4Addr, Ipv4Addr),
    V6(Ipv6Addr, Ipv6Addr),
}

const fn hosts(family: Family, direction: Direction) -> Hosts {
    match family {
        Family::Ipv4 => {
            let (source, destination) = oriented(direction, IPV4_CLIENT, IPV4_SERVER);
            Hosts::V4(source, destination)
        }
        Family::Ipv6 => {
            let (source, destination) = oriented(direction, IPV6_CLIENT, IPV6_SERVER);
            Hosts::V6(source, destination)
        }
    }
}

fn pseudo_header(hosts: Hosts, length: usize) -> Vec<u8> {
    let length = u32::try_from(length).expect("segment payload is bounded");
    match hosts {
        Hosts::V4(source, destination) => [
            &source.octets()[..],
            &destination.octets(),
            &[0, TCP],
            &length.to_be_bytes()[2..],
        ]
        .concat(),
        Hosts::V6(source, destination) => [
            &source.octets()[..],
            &destination.octets(),
            &length.to_be_bytes(),
            &[0, 0, 0, TCP],
        ]
        .concat(),
    }
}

pub fn tcp(conversation: Conversation, direction: Direction, segment: &Segment<'_>) -> Vec<u8> {
    let (source, destination) = oriented(
        direction,
        conversation.client_port,
        conversation.server_port,
    );
    let payload = &segment.payload[..segment.payload.len().min(MAX_SEGMENT_PAYLOAD)];
    let encode = |checksum: u16| {
        [
            &source.to_be_bytes()[..],
            &destination.to_be_bytes(),
            &segment.sequence.to_be_bytes(),
            &segment.acknowledgment.to_be_bytes(),
            &[0x50, segment.flags],
            &segment.window.to_be_bytes(),
            &checksum.to_be_bytes(),
            &[0, 0],
            payload,
        ]
        .concat()
    };
    let unchecked = encode(0);
    let pseudo = pseudo_header(hosts(conversation.family, direction), unchecked.len());
    encode(checksum_parts(&[&pseudo, &unchecked]))
}

/// Wraps TCP bytes, or a fragment of them, in one IP packet. `payload` must
/// not exceed a [`tcp`] segment built from [`MAX_SEGMENT_PAYLOAD`] bytes.
pub fn ip(
    conversation: Conversation,
    direction: Direction,
    identification: u32,
    fragment: Option<Fragment>,
    payload: &[u8],
) -> Vec<u8> {
    match hosts(conversation.family, direction) {
        Hosts::V4(source, destination) => {
            ipv4(source, destination, identification, fragment, payload)
        }
        Hosts::V6(source, destination) => {
            ipv6(source, destination, identification, fragment, payload)
        }
    }
}

fn ipv4(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    identification: u32,
    fragment: Option<Fragment>,
    payload: &[u8],
) -> Vec<u8> {
    let total = u16::try_from(20 + payload.len()).expect("segment payload is bounded");
    let flags_offset = fragment.map_or(0, |fragment| {
        (u16::from(fragment.more) << 13) | (fragment.offset_units & 0x1fff)
    });
    let header = |checksum: u16| {
        [
            &[0x45, 0][..],
            &total.to_be_bytes(),
            &identification.to_be_bytes()[2..],
            &flags_offset.to_be_bytes(),
            &[64, TCP],
            &checksum.to_be_bytes(),
            &source.octets(),
            &destination.octets(),
        ]
        .concat()
    };
    [header(checksum_parts(&[&header(0)])), payload.to_vec()].concat()
}

fn ipv6(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    identification: u32,
    fragment: Option<Fragment>,
    payload: &[u8],
) -> Vec<u8> {
    let extension: Vec<u8> = fragment.map_or_else(Vec::new, |fragment| {
        let offset_more = (fragment.offset_units << 3) | u16::from(fragment.more);
        [
            &[TCP, 0][..],
            &offset_more.to_be_bytes(),
            &identification.to_be_bytes(),
        ]
        .concat()
    });
    let next_header = if fragment.is_some() {
        IPV6_FRAGMENT
    } else {
        TCP
    };
    let length =
        u16::try_from(extension.len() + payload.len()).expect("segment payload is bounded");
    [
        &[0x60, 0, 0, 0][..],
        &length.to_be_bytes(),
        &[next_header, 64],
        &source.octets(),
        &destination.octets(),
        &extension,
        payload,
    ]
    .concat()
}

/// Serializes raw-IP frames into a classic PCAP and opens it for analysis.
pub fn capture(frames: impl IntoIterator<Item = (SystemTime, Vec<u8>)>) -> Reader<Cursor<Vec<u8>>> {
    let mut writer = Writer::new(Vec::new(), Format::Pcap, LinkType::RAW)
        .expect("an in-memory PCAP writer opens");
    for (timestamp, bytes) in frames {
        let frame = Frame::new(Some(timestamp), LinkType::RAW, bytes)
            .expect("a bounded raw-IP frame is valid");
        writer
            .write_frame(&frame)
            .expect("a bounded raw-IP frame fits the default PCAP limits");
    }
    Reader::with_limits(Cursor::new(writer.into_inner()), ReaderLimits::default())
        .expect("a freshly written PCAP opens")
}
