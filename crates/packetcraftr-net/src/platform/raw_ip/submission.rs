// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Target socket ownership, interface binding, and native error mapping.

#![cfg_attr(windows, allow(unsafe_code))]
#![cfg_attr(not(windows), forbid(unsafe_code))]

#[cfg(target_os = "macos")]
use std::num::NonZeroU32;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6},
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
#[cfg(windows)]
use windows::Win32::Networking::WinSock::{
    IP_MULTICAST_IF, IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_MULTICAST_IF, IPV6_UNICAST_IF,
    SOCKET, SOCKET_ERROR, WSAGetLastError, setsockopt,
};

use super::{
    super::super::Error as LiveIoError,
    super::InterfaceId,
    preparation::{IpFamily, PreparedRawIp},
};

const IPPROTO_RAW: i32 = 255;

#[derive(Debug)]
pub(super) struct RawSocketError {
    pub(super) operation: &'static str,
    pub(super) source: io::Error,
}

pub(super) trait RawIpBackend {
    fn send(&self, packet: &PreparedRawIp) -> Result<usize, RawSocketError>;
}

pub(super) struct SystemRawIpBackend;

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
fn bind_interface(socket: &Socket, packet: &PreparedRawIp) -> Result<(), RawSocketError> {
    let (level, option, index) = match packet.family {
        IpFamily::V4 => (
            IPPROTO_IP.0,
            if packet.destination.is_multicast() {
                IP_MULTICAST_IF
            } else {
                IP_UNICAST_IF
            },
            packet.interface.index.to_be_bytes(),
        ),
        IpFamily::V6 => (
            IPPROTO_IPV6.0,
            if packet.destination.is_multicast() {
                IPV6_MULTICAST_IF
            } else {
                IPV6_UNICAST_IF
            },
            packet.interface.index.to_ne_bytes(),
        ),
    };
    let raw_socket = usize::try_from(socket.as_raw_socket()).map_err(|_| {
        raw_error(
            "binding the selected Windows interface",
            io::Error::new(io::ErrorKind::InvalidInput, "socket handle exceeds usize"),
        )
    })?;
    // SAFETY: socket2 owns a live Winsock SOCKET for the duration of this
    // call, and `index` is the documented four-byte IF_INDEX option value.
    let result = unsafe { setsockopt(SOCKET(raw_socket), level, option, Some(&index)) };
    if result == SOCKET_ERROR {
        // SAFETY: WSAGetLastError has no preconditions and is read
        // immediately after the failed Winsock call on the same thread.
        let code = unsafe { WSAGetLastError().0 };
        Err(raw_error(
            "binding the selected Windows interface",
            io::Error::from_raw_os_error(code),
        ))
    } else {
        Ok(())
    }
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

#[cfg(target_os = "macos")]
pub(super) fn validate_platform_support(packet: &PreparedRawIp) -> Result<(), LiveIoError> {
    if packet.family == IpFamily::V6 {
        return Err(LiveIoError::Unsupported {
            message: "Darwin raw IPv6 sockets synthesize the IPv6 header and do not support IPV6_HDRINCL; exact complete-header transmission requires an explicit Layer 2 path"
                .to_owned(),
        });
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub(super) fn validate_platform_support(_packet: &PreparedRawIp) -> Result<(), LiveIoError> {
    Ok(())
}

pub(super) fn raw_error(operation: &'static str, source: io::Error) -> RawSocketError {
    RawSocketError { operation, source }
}

pub(super) fn map_raw_error(interface: &InterfaceId, error: RawSocketError) -> LiveIoError {
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
