// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(test)]

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Mutex,
};

use super::{
    preparation::{PreparedRawIp, checksum, macos_ipv4_submission, upper_protocol},
    send_with_backend,
    submission::{RawIpBackend, RawSocketError, raw_error},
};
use crate::{
    Error as LiveIoError,
    link::{LinkCapability, LinkMode},
    route::{
        DestinationScope, InterfaceId, MaterializedRoute, PlannedRoute, RouteDecision,
        RouteSelectionReason,
    },
    transmit::Layer3Frame,
};
use bytes::Bytes;
use packetcraftr_core::frame::LinkType;

struct RecordingBackend {
    packet: Mutex<Option<PreparedRawIp>>,
    result: Mutex<Option<Result<usize, RawSocketError>>>,
}

impl RecordingBackend {
    fn complete() -> Self {
        Self {
            packet: Mutex::new(None),
            result: Mutex::new(None),
        }
    }
}

impl RawIpBackend for RecordingBackend {
    fn send(&self, packet: &PreparedRawIp) -> Result<usize, RawSocketError> {
        *self.packet.lock().unwrap() = Some(packet.clone());
        self.result
            .lock()
            .unwrap()
            .take()
            .unwrap_or(Ok(packet.submission.len()))
    }
}

fn route(source: IpAddr, destination: IpAddr, mtu: u32) -> MaterializedRoute {
    MaterializedRoute {
        plan: PlannedRoute {
            route: RouteDecision {
                interface: InterfaceId {
                    name: "test0".to_owned(),
                    index: 7,
                },
                source_mac: None,
                selected_address: Some(source),
                preferred_source: None,
                next_hop: None,
                selection_reason: RouteSelectionReason::OnLink,
                destination_scope: DestinationScope::Private,
                mtu,
                capability: LinkCapability::Layer3,
                link_type: if source.is_ipv4() {
                    LinkType::IPV4
                } else {
                    LinkType::IPV6
                },
            },
            mode: LinkMode::Layer3,
            lookup_destination: Some(destination),
            final_destination: Some(destination),
            visited_destinations: vec![destination],
            packet_source: Some(source),
            neighbor_source: Some(source),
            neighbor_target: None,
            destination_mac: None,
            source_mac: None,
            neighbor_vlan_tags: Vec::new(),
            synthesized_ethernet: false,
        },
        neighbor_resolution: None,
    }
}

fn ipv4(source: Ipv4Addr, destination: Ipv4Addr) -> Bytes {
    let mut bytes = vec![
        0x45,
        0,
        0,
        24,
        0x12,
        0x34,
        0x40,
        0,
        64,
        253,
        0,
        0,
        source.octets()[0],
        source.octets()[1],
        source.octets()[2],
        source.octets()[3],
        destination.octets()[0],
        destination.octets()[1],
        destination.octets()[2],
        destination.octets()[3],
        1,
        2,
        3,
        4,
    ];
    let checksum = checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    Bytes::from(bytes)
}

fn ipv6(source: Ipv6Addr, destination: Ipv6Addr) -> Bytes {
    let mut bytes = vec![0x60, 0, 0, 0, 0, 4, 253, 64];
    bytes.extend_from_slice(&source.octets());
    bytes.extend_from_slice(&destination.octets());
    bytes.extend_from_slice(&[1, 2, 3, 4]);
    Bytes::from(bytes)
}

#[test]
fn preserves_spoofed_ipv4_bytes_while_binding_interface_source() {
    let interface_source = Ipv4Addr::new(192, 0, 2, 10);
    let packet_source = Ipv4Addr::new(203, 0, 113, 99);
    let destination = Ipv4Addr::new(198, 51, 100, 1);
    let route = route(interface_source.into(), destination.into(), 1_500);
    let bytes = ipv4(packet_source, destination);
    let backend = RecordingBackend::complete();

    let report =
        send_with_backend(Layer3Frame::try_new(&bytes, &route).unwrap(), &backend).unwrap();

    assert_eq!(report.bytes_sent, bytes.len());
    assert_eq!(report.wire_bytes, bytes.clone());
    let packet = backend.packet.lock().unwrap().clone().unwrap();
    assert_eq!(packet.interface_source, IpAddr::V4(interface_source));
    assert_eq!(packet.destination, IpAddr::V4(destination));
    assert_eq!(packet.wire_bytes, bytes);
}

#[test]
fn sends_exact_ipv6_frame() {
    let source: Ipv6Addr = "2001:db8::10".parse().unwrap();
    let destination: Ipv6Addr = "2001:db8::20".parse().unwrap();
    let route = route(source.into(), destination.into(), 1_280);
    let bytes = ipv6(source, destination);
    let backend = RecordingBackend::complete();

    #[cfg(not(target_os = "macos"))]
    {
        let report =
            send_with_backend(Layer3Frame::try_new(&bytes, &route).unwrap(), &backend).unwrap();
        assert_eq!(report.wire_bytes, bytes);
    }
    #[cfg(target_os = "macos")]
    {
        assert!(matches!(
            send_with_backend(Layer3Frame::try_new(&bytes, &route).unwrap(), &backend),
            Err(LiveIoError::Unsupported { .. })
        ));
        assert!(backend.packet.lock().unwrap().is_none());
    }
}

#[test]
fn partial_native_write_fails_closed() {
    let source = Ipv4Addr::new(192, 0, 2, 10);
    let destination = Ipv4Addr::new(198, 51, 100, 1);
    let route = route(source.into(), destination.into(), 1_500);
    let bytes = ipv4(source, destination);
    let backend = RecordingBackend {
        packet: Mutex::new(None),
        result: Mutex::new(Some(Ok(bytes.len() - 1))),
    };

    assert!(matches!(
        send_with_backend(Layer3Frame::try_new(&bytes, &route).unwrap(), &backend),
        Err(LiveIoError::PartialSend { .. })
    ));
}

#[test]
fn operating_system_rewrites_are_rejected_before_side_effects() {
    let source = Ipv4Addr::new(192, 0, 2, 10);
    let destination = Ipv4Addr::new(198, 51, 100, 1);
    let route = route(source.into(), destination.into(), 1_500);
    let valid = ipv4(source, destination);
    let mut cases = Vec::new();
    let mut zero_id = valid.to_vec();
    zero_id[4..6].copy_from_slice(&[0, 0]);
    cases.push(zero_id);
    let mut wrong_length = valid.to_vec();
    wrong_length[3] -= 1;
    cases.push(wrong_length);
    let mut wrong_checksum = valid.to_vec();
    wrong_checksum[10] ^= 0xff;
    cases.push(wrong_checksum);

    for bytes in cases {
        let bytes = Bytes::from(bytes);
        let backend = RecordingBackend::complete();
        assert!(matches!(
            send_with_backend(Layer3Frame::try_new(&bytes, &route).unwrap(), &backend),
            Err(LiveIoError::InvalidTransmissionFrame { .. })
        ));
        assert!(backend.packet.lock().unwrap().is_none());
    }
}

#[test]
fn destination_family_and_mtu_are_validated_before_side_effects() {
    let source = Ipv4Addr::new(192, 0, 2, 10);
    let destination = Ipv4Addr::new(198, 51, 100, 1);
    let bytes = ipv4(source, destination);
    for route in [
        route(source.into(), Ipv4Addr::new(198, 51, 100, 2).into(), 1_500),
        route(source.into(), destination.into(), 20),
    ] {
        let backend = RecordingBackend::complete();
        assert!(matches!(
            send_with_backend(Layer3Frame::try_new(&bytes, &route).unwrap(), &backend),
            Err(LiveIoError::InvalidTransmissionFrame { .. })
        ));
        assert!(backend.packet.lock().unwrap().is_none());
    }
}

#[test]
fn macos_submission_changes_only_host_order_kernel_fields() {
    let source = Ipv4Addr::new(192, 0, 2, 10);
    let destination = Ipv4Addr::new(198, 51, 100, 1);
    let bytes = ipv4(source, destination);
    let submission = macos_ipv4_submission(&bytes);

    assert_eq!(&submission[2..4], &24_u16.to_ne_bytes());
    assert_eq!(&submission[6..8], &0x4000_u16.to_ne_bytes());
    assert_eq!(&submission[..2], &bytes[..2]);
    assert_eq!(&submission[8..], &bytes[8..]);
}

#[test]
fn ipv6_upper_protocol_walks_bounded_extension_headers() {
    let source: Ipv6Addr = "2001:db8::10".parse().unwrap();
    let destination: Ipv6Addr = "2001:db8::20".parse().unwrap();
    let mut bytes = ipv6(source, destination).to_vec();
    bytes[4..6].copy_from_slice(&12_u16.to_be_bytes());
    bytes[6] = 0;
    bytes.splice(40..40, [6, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(upper_protocol(&bytes).unwrap(), 6);

    bytes.truncate(41);
    assert!(matches!(
        upper_protocol(&bytes),
        Err(LiveIoError::InvalidTransmissionFrame { .. })
    ));
}

#[test]
fn permission_errors_remain_typed() {
    let source = Ipv4Addr::new(192, 0, 2, 10);
    let destination = Ipv4Addr::new(198, 51, 100, 1);
    let route = route(source.into(), destination.into(), 1_500);
    let bytes = ipv4(source, destination);
    let backend = RecordingBackend {
        packet: Mutex::new(None),
        result: Mutex::new(Some(Err(raw_error(
            "opening a raw IP socket",
            io::Error::from(io::ErrorKind::PermissionDenied),
        )))),
    };

    assert!(matches!(
        send_with_backend(Layer3Frame::try_new(&bytes, &route).unwrap(), &backend),
        Err(LiveIoError::Privilege { .. })
    ));
}

#[cfg(windows)]
#[test]
fn windows_rejects_spoofed_udp_before_the_native_send() {
    let interface_source = Ipv4Addr::new(192, 0, 2, 10);
    let packet_source = Ipv4Addr::new(203, 0, 113, 99);
    let destination = Ipv4Addr::new(198, 51, 100, 1);
    let route = route(interface_source.into(), destination.into(), 1_500);
    let mut bytes = ipv4(packet_source, destination).to_vec();
    bytes[9] = 17;
    bytes[10..12].copy_from_slice(&[0, 0]);
    let header_checksum = checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    let bytes = Bytes::from(bytes);
    let backend = RecordingBackend::complete();

    assert!(matches!(
        send_with_backend(Layer3Frame::try_new(&bytes, &route).unwrap(), &backend),
        Err(LiveIoError::Unsupported { .. })
    ));
    assert!(backend.packet.lock().unwrap().is_none());
}
