// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Target-native raw IPv4/IPv6 transmission.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
#[cfg(target_os = "macos")]
use std::num::NonZeroU32;

use bytes::Bytes;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use super::super::{IoSendReport, Layer3Frame, LiveIoError};
use super::InterfaceId;

const IPV4_MINIMUM_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const IPPROTO_RAW: i32 = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IpFamily {
    V4,
    V6,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedRawIp {
    family: IpFamily,
    interface: InterfaceId,
    interface_source: IpAddr,
    destination: IpAddr,
    submission: Bytes,
    wire_bytes: Bytes,
}

#[derive(Debug)]
struct RawSocketError {
    operation: &'static str,
    source: io::Error,
}

trait RawIpBackend {
    fn send(&self, packet: &PreparedRawIp) -> Result<usize, RawSocketError>;
}

struct SystemRawIpBackend;

impl RawIpBackend for SystemRawIpBackend {
    fn send(&self, packet: &PreparedRawIp) -> Result<usize, RawSocketError> {
        let domain = match packet.family {
            IpFamily::V4 => Domain::IPV4,
            IpFamily::V6 => Domain::IPV6,
        };
        let socket = Socket::new(domain, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))
            .map_err(|source| raw_error("opening a raw IP socket", source))?;
        match packet.family {
            IpFamily::V4 => socket
                .set_header_included_v4(true)
                .map_err(|source| raw_error("enabling IPv4 header inclusion", source))?,
            IpFamily::V6 => socket
                .set_header_included_v6(true)
                .map_err(|source| raw_error("enabling IPv6 header inclusion", source))?,
        }

        bind_interface(&socket, packet)?;
        bind_route_source(&socket, packet)?;
        if packet.destination == IpAddr::V4(Ipv4Addr::BROADCAST) {
            socket
                .set_broadcast(true)
                .map_err(|source| raw_error("enabling IPv4 broadcast", source))?;
        }
        socket
            .send_to(
                &packet.submission,
                &socket_address(packet.destination, packet.interface.index),
            )
            .map_err(|source| raw_error("sending the raw IP datagram", source))
    }
}

#[cfg(target_os = "linux")]
fn bind_interface(socket: &Socket, packet: &PreparedRawIp) -> Result<(), RawSocketError> {
    socket
        .bind_device(Some(packet.interface.name.as_bytes()))
        .map_err(|source| raw_error("binding the selected Linux interface", source))
}

#[cfg(target_os = "macos")]
fn bind_interface(socket: &Socket, packet: &PreparedRawIp) -> Result<(), RawSocketError> {
    let index = NonZeroU32::new(packet.interface.index).ok_or_else(|| {
        raw_error(
            "binding the selected macOS interface",
            io::Error::new(io::ErrorKind::InvalidInput, "interface index is zero"),
        )
    })?;
    match packet.family {
        IpFamily::V4 => socket.bind_device_by_index_v4(Some(index)),
        IpFamily::V6 => socket.bind_device_by_index_v6(Some(index)),
    }
    .map_err(|source| raw_error("binding the selected macOS interface", source))
}

#[cfg(windows)]
fn bind_interface(_socket: &Socket, _packet: &PreparedRawIp) -> Result<(), RawSocketError> {
    // Binding the route-selected source address below constrains Winsock to
    // that address and its owning interface without exposing a socket handle.
    Ok(())
}

#[cfg(not(windows))]
fn bind_route_source(_socket: &Socket, _packet: &PreparedRawIp) -> Result<(), RawSocketError> {
    // Linux SO_BINDTODEVICE and macOS IP_BOUND_IF constrain the route without
    // making a crafted source address fail local-address validation.
    Ok(())
}

#[cfg(windows)]
fn bind_route_source(socket: &Socket, packet: &PreparedRawIp) -> Result<(), RawSocketError> {
    // Winsock has no socket2 interface-index binding. The route-selected
    // source is assigned to exactly one adapter by the native route provider.
    socket
        .bind(&socket_address(
            packet.interface_source,
            packet.interface.index,
        ))
        .map_err(|source| raw_error("binding the route-selected source address", source))
}

fn socket_address(address: IpAddr, interface_index: u32) -> SockAddr {
    match address {
        IpAddr::V4(address) => SocketAddr::from((address, 0)).into(),
        IpAddr::V6(address) => {
            let scope_id = if address.is_unicast_link_local() || address.is_multicast() {
                interface_index
            } else {
                0
            };
            SocketAddr::V6(SocketAddrV6::new(address, 0, 0, scope_id)).into()
        }
    }
}

pub(super) fn send_layer3(frame: Layer3Frame<'_>) -> Result<IoSendReport, LiveIoError> {
    send_with(frame, &SystemRawIpBackend)
}

fn send_with<B: RawIpBackend>(
    frame: Layer3Frame<'_>,
    backend: &B,
) -> Result<IoSendReport, LiveIoError> {
    let packet = prepare(frame)?;
    let actual = backend
        .send(&packet)
        .map_err(|error| map_raw_error(&packet.interface, error))?;
    let expected = packet.submission.len();
    if actual != expected {
        return Err(LiveIoError::PartialSend { expected, actual });
    }
    Ok(IoSendReport {
        bytes_sent: packet.wire_bytes.len(),
        wire_bytes: Some(packet.wire_bytes),
    })
}

fn prepare(frame: Layer3Frame<'_>) -> Result<PreparedRawIp, LiveIoError> {
    let bytes = frame.bytes().clone();
    let plan = &frame.route().plan;
    if bytes.len() > plan.route.mtu as usize {
        return Err(invalid_frame(format!(
            "{} bytes exceed route MTU {}",
            bytes.len(),
            plan.route.mtu
        )));
    }
    if plan.route.interface.name.is_empty() || plan.route.interface.index == 0 {
        return Err(invalid_frame(
            "route-selected interface identity is incomplete".to_owned(),
        ));
    }
    let interface_source = plan
        .route
        .selected_address
        .or(plan.route.preferred_source)
        .ok_or_else(|| invalid_frame("route has no interface-owned source address".to_owned()))?;
    let route_destination = plan
        .lookup_destination
        .ok_or_else(|| invalid_frame("route has no Layer 3 lookup destination".to_owned()))?;
    let Some(version) = bytes.first().map(|byte| byte >> 4) else {
        return Err(invalid_frame("packet is empty".to_owned()));
    };

    let (family, packet_source, destination, submission) = match version {
        4 => {
            let (source, destination) = validate_ipv4(&bytes)?;
            (
                IpFamily::V4,
                IpAddr::V4(source),
                IpAddr::V4(destination),
                ipv4_submission(&bytes),
            )
        }
        6 => {
            let (source, destination) = validate_ipv6(&bytes)?;
            (
                IpFamily::V6,
                IpAddr::V6(source),
                IpAddr::V6(destination),
                bytes.clone(),
            )
        }
        version => return Err(invalid_frame(format!("unsupported IP version {version}"))),
    };
    if interface_source.is_ipv4() != matches!(family, IpFamily::V4) {
        return Err(invalid_frame(
            "route-selected source address family differs from packet family".to_owned(),
        ));
    }
    if route_destination != destination {
        return Err(invalid_frame(format!(
            "packet destination {destination} differs from route lookup destination {route_destination}"
        )));
    }
    if packet_source.is_unspecified() {
        return Err(invalid_frame(
            "packet source is unspecified and would be changed by the operating system".to_owned(),
        ));
    }

    #[cfg(windows)]
    validate_windows_restrictions(&bytes, packet_source, interface_source)?;

    Ok(PreparedRawIp {
        family,
        interface: plan.route.interface.clone(),
        interface_source,
        destination,
        submission,
        wire_bytes: bytes,
    })
}

fn validate_ipv4(bytes: &[u8]) -> Result<(Ipv4Addr, Ipv4Addr), LiveIoError> {
    if bytes.len() < IPV4_MINIMUM_HEADER {
        return Err(invalid_frame("truncated IPv4 header".to_owned()));
    }
    let header_length = usize::from(bytes[0] & 0x0f) * 4;
    if header_length < IPV4_MINIMUM_HEADER || header_length > bytes.len() {
        return Err(invalid_frame(format!(
            "invalid IPv4 header length {header_length}"
        )));
    }
    let declared = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if declared != bytes.len() {
        return Err(invalid_frame(format!(
            "IPv4 total length {declared} differs from submitted {} bytes",
            bytes.len()
        )));
    }
    if bytes[4..6] == [0, 0] {
        return Err(invalid_frame(
            "IPv4 identification is zero and would be replaced by the operating system".to_owned(),
        ));
    }
    if checksum(&bytes[..header_length]) != 0 {
        return Err(invalid_frame(
            "IPv4 header checksum would be rewritten by the operating system".to_owned(),
        ));
    }
    let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    if destination.is_unspecified() {
        return Err(invalid_frame("IPv4 destination is unspecified".to_owned()));
    }
    Ok((source, destination))
}

fn validate_ipv6(bytes: &[u8]) -> Result<(Ipv6Addr, Ipv6Addr), LiveIoError> {
    if bytes.len() < IPV6_HEADER {
        return Err(invalid_frame("truncated IPv6 header".to_owned()));
    }
    let actual_payload = bytes.len() - IPV6_HEADER;
    let declared_payload = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    if declared_payload != actual_payload {
        return Err(invalid_frame(format!(
            "IPv6 payload length {declared_payload} differs from submitted {actual_payload} bytes"
        )));
    }
    let source = ipv6_address(&bytes[8..24]);
    let destination = ipv6_address(&bytes[24..40]);
    if destination.is_unspecified() {
        return Err(invalid_frame("IPv6 destination is unspecified".to_owned()));
    }
    Ok((source, destination))
}

fn ipv6_address(bytes: &[u8]) -> Ipv6Addr {
    let mut address = [0; 16];
    address.copy_from_slice(bytes);
    Ipv6Addr::from(address)
}

#[cfg(target_os = "macos")]
fn ipv4_submission(bytes: &Bytes) -> Bytes {
    macos_ipv4_submission(bytes)
}

#[cfg(not(target_os = "macos"))]
fn ipv4_submission(bytes: &Bytes) -> Bytes {
    bytes.clone()
}

#[cfg(any(test, target_os = "macos"))]
fn macos_ipv4_submission(bytes: &Bytes) -> Bytes {
    let mut submission = bytes.to_vec();
    let total_length = u16::from_be_bytes([submission[2], submission[3]]);
    submission[2..4].copy_from_slice(&total_length.to_ne_bytes());
    let flags_and_offset = u16::from_be_bytes([submission[6], submission[7]]);
    submission[6..8].copy_from_slice(&flags_and_offset.to_ne_bytes());
    Bytes::from(submission)
}

#[cfg(windows)]
fn validate_windows_restrictions(
    bytes: &[u8],
    packet_source: IpAddr,
    interface_source: IpAddr,
) -> Result<(), LiveIoError> {
    let protocol = upper_protocol(bytes)?;
    if protocol == 17 && packet_source != interface_source {
        return Err(LiveIoError::Unsupported {
            message: "Windows client editions drop raw UDP with a source not assigned to a local interface"
                .to_owned(),
        });
    }
    Ok(())
}

#[cfg(any(test, windows))]
fn upper_protocol(bytes: &[u8]) -> Result<u8, LiveIoError> {
    if bytes[0] >> 4 == 4 {
        return Ok(bytes[9]);
    }
    let mut next = bytes[6];
    let mut offset = IPV6_HEADER;
    loop {
        let header_length = match next {
            // Hop-by-Hop, Routing, and Destination Options.
            0 | 43 | 60 => {
                let header = bytes
                    .get(offset..offset + 2)
                    .ok_or_else(|| invalid_frame("truncated IPv6 extension header".to_owned()))?;
                next = header[0];
                usize::from(header[1])
                    .checked_add(1)
                    .and_then(|units| units.checked_mul(8))
                    .ok_or_else(|| invalid_frame("IPv6 extension length overflowed".to_owned()))?
            }
            // Fragment.
            44 => {
                next = *bytes
                    .get(offset)
                    .ok_or_else(|| invalid_frame("truncated IPv6 fragment header".to_owned()))?;
                8
            }
            // Authentication Header.
            51 => {
                let header = bytes.get(offset..offset + 2).ok_or_else(|| {
                    invalid_frame("truncated IPv6 authentication header".to_owned())
                })?;
                next = header[0];
                usize::from(header[1])
                    .checked_add(2)
                    .and_then(|units| units.checked_mul(4))
                    .ok_or_else(|| {
                        invalid_frame("IPv6 authentication length overflowed".to_owned())
                    })?
            }
            _ => return Ok(next),
        };
        offset = offset
            .checked_add(header_length)
            .filter(|offset| *offset <= bytes.len())
            .ok_or_else(|| invalid_frame("IPv6 extension exceeds packet bytes".to_owned()))?;
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u64;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u64::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(byte) = chunks.remainder().first() {
        sum += u64::from(u16::from_be_bytes([*byte, 0]));
    }
    while sum > u64::from(u16::MAX) {
        sum = (sum & u64::from(u16::MAX)) + (sum >> 16);
    }
    !(sum as u16)
}

fn raw_error(operation: &'static str, source: io::Error) -> RawSocketError {
    RawSocketError { operation, source }
}

fn map_raw_error(interface: &InterfaceId, error: RawSocketError) -> LiveIoError {
    let message = format!("{}: {}", error.operation, error.source);
    match error.source.kind() {
        io::ErrorKind::PermissionDenied => LiveIoError::Privilege { message },
        io::ErrorKind::Unsupported => LiveIoError::Unsupported { message },
        io::ErrorKind::NotFound => LiveIoError::Device {
            interface: interface.name.clone(),
            message,
        },
        _ => LiveIoError::Send { message },
    }
}

fn invalid_frame(message: String) -> LiveIoError {
    LiveIoError::InvalidTransmissionFrame { message }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::io::{
        DestinationScope, LinkCapability, LinkMode, LinkType, MaterializedRoute, PlannedRoute,
        RouteDecision, RouteSelectionReason,
    };

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

        let report = send_with(Layer3Frame::try_new(&bytes, &route).unwrap(), &backend).unwrap();

        assert_eq!(report.bytes_sent, bytes.len());
        assert_eq!(report.wire_bytes, Some(bytes.clone()));
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

        let report = send_with(Layer3Frame::try_new(&bytes, &route).unwrap(), &backend).unwrap();

        assert_eq!(report.wire_bytes, Some(bytes));
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
            send_with(Layer3Frame::try_new(&bytes, &route).unwrap(), &backend),
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
                send_with(Layer3Frame::try_new(&bytes, &route).unwrap(), &backend),
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
                send_with(Layer3Frame::try_new(&bytes, &route).unwrap(), &backend),
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
            send_with(Layer3Frame::try_new(&bytes, &route).unwrap(), &backend),
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
            send_with(Layer3Frame::try_new(&bytes, &route).unwrap(), &backend),
            Err(LiveIoError::Unsupported { .. })
        ));
        assert!(backend.packet.lock().unwrap().is_none());
    }
}
