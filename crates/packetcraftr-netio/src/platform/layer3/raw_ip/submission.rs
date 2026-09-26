// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Target socket ownership, interface binding, and native error mapping.

#![cfg_attr(windows, allow(unsafe_code))]

#[cfg(target_os = "macos")]
use std::num::NonZeroU32;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::sync::Arc;
use std::{
    io,
    net::{IpAddr, SocketAddr, SocketAddrV6},
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
#[cfg(windows)]
use windows::Win32::Networking::WinSock::{
    IP_MULTICAST_IF, IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_MULTICAST_IF, IPV6_UNICAST_IF,
    SOCKET, SOCKET_ERROR, WSAGetLastError, setsockopt,
};

use super::preparation::PreparedRawIp;
use crate::Error;
use crate::interface::Id as InterfaceId;

const IPPROTO_RAW: i32 = 255;

#[derive(Debug)]
pub(super) struct RawSocketError {
    pub(super) operation: &'static str,
    pub(super) source: io::Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RawSocketOption {
    Ipv4HeaderIncluded,
    Ipv4Broadcast,
    Ipv6HeaderIncluded,
}

impl RawSocketOption {
    fn operation(self) -> &'static str {
        match self {
            Self::Ipv4HeaderIncluded => "enabling IPv4 header inclusion",
            Self::Ipv4Broadcast => "enabling IPv4 broadcast permission",
            Self::Ipv6HeaderIncluded => "enabling IPv6 header inclusion",
        }
    }
}

fn configure_socket_options(
    destination: IpAddr,
    mut apply: impl FnMut(RawSocketOption) -> io::Result<()>,
) -> Result<(), RawSocketError> {
    let options: &[RawSocketOption] = match destination {
        IpAddr::V4(_) => &[
            RawSocketOption::Ipv4HeaderIncluded,
            RawSocketOption::Ipv4Broadcast,
        ],
        IpAddr::V6(_) => &[RawSocketOption::Ipv6HeaderIncluded],
    };
    for option in options {
        apply(*option).map_err(|source| raw_error(option.operation(), source))?;
    }
    Ok(())
}

pub(super) fn send(packet: &PreparedRawIp) -> Result<usize, RawSocketError> {
    let domain = match packet.destination {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))
        .map_err(|source| raw_error("opening a raw IP socket", source))?;
    configure_socket_options(packet.destination, |option| match option {
        RawSocketOption::Ipv4HeaderIncluded => socket.set_header_included_v4(true),
        RawSocketOption::Ipv4Broadcast => socket.set_broadcast(true),
        RawSocketOption::Ipv6HeaderIncluded => socket.set_header_included_v6(true),
    })?;

    bind_interface(&socket, packet)?;
    socket
        .send_to(
            &packet.submission,
            &socket_address(packet.destination, packet.interface.index),
        )
        .map_err(|source| raw_error("sending the raw IP datagram", source))
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
    match packet.destination {
        IpAddr::V4(_) => socket.bind_device_by_index_v4(Some(index)),
        IpAddr::V6(_) => socket.bind_device_by_index_v6(Some(index)),
    }
    .map_err(|source| raw_error("binding the selected macOS interface", source))
}

#[cfg(windows)]
fn bind_interface(socket: &Socket, packet: &PreparedRawIp) -> Result<(), RawSocketError> {
    let (level, option, index) = match packet.destination {
        IpAddr::V4(_) => (
            IPPROTO_IP.0,
            if packet.destination.is_multicast() {
                IP_MULTICAST_IF
            } else {
                IP_UNICAST_IF
            },
            packet.interface.index.to_be_bytes(),
        ),
        IpAddr::V6(_) => (
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
pub(super) fn validate_platform_support(packet: &PreparedRawIp) -> Result<(), Error> {
    if packet.destination.is_ipv6() {
        return Err(Error::Unsupported {
            message: "Darwin raw IPv6 sockets synthesize the IPv6 header and do not support IPV6_HDRINCL; exact complete-header transmission requires an explicit Layer 2 path"
                .to_owned(),
         source: None });
    }
    Ok(())
}

pub(super) fn raw_error(operation: &'static str, source: io::Error) -> RawSocketError {
    RawSocketError { operation, source }
}

pub(super) fn map_raw_error(interface: &InterfaceId, error: RawSocketError) -> Error {
    let message = error.operation.to_owned();
    let kind = error.source.kind();
    let source: Option<crate::SystemFault> = Some(Arc::new(error.source));
    match kind {
        io::ErrorKind::PermissionDenied => Error::Privilege { message, source },
        io::ErrorKind::Unsupported => Error::Unsupported { message, source },
        io::ErrorKind::NotFound => Error::Device {
            interface: interface.name.clone(),
            message,
            source,
        },
        _ => Error::Send { message, source },
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn raw_socket_option_policy_enables_broadcast_for_every_ipv4_socket_before_send() {
        #[derive(Debug, PartialEq, Eq)]
        enum Operation {
            Option(RawSocketOption),
            Send,
        }

        let cases = [
            (
                "unicast IPv4",
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                vec![
                    Operation::Option(RawSocketOption::Ipv4HeaderIncluded),
                    Operation::Option(RawSocketOption::Ipv4Broadcast),
                    Operation::Send,
                ],
            ),
            (
                "limited IPv4 broadcast",
                IpAddr::V4(Ipv4Addr::BROADCAST),
                vec![
                    Operation::Option(RawSocketOption::Ipv4HeaderIncluded),
                    Operation::Option(RawSocketOption::Ipv4Broadcast),
                    Operation::Send,
                ],
            ),
            (
                "subnet-directed IPv4 broadcast",
                IpAddr::V4(Ipv4Addr::new(10, 23, 0, 255)),
                vec![
                    Operation::Option(RawSocketOption::Ipv4HeaderIncluded),
                    Operation::Option(RawSocketOption::Ipv4Broadcast),
                    Operation::Send,
                ],
            ),
            (
                "IPv6",
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                vec![
                    Operation::Option(RawSocketOption::Ipv6HeaderIncluded),
                    Operation::Send,
                ],
            ),
        ];

        for (name, destination, expected) in cases {
            let mut operations = Vec::new();
            configure_socket_options(destination, |option| {
                operations.push(Operation::Option(option));
                Ok(())
            })
            .expect("fixture socket options succeed");
            operations.push(Operation::Send);
            assert_eq!(operations, expected, "{name}");
        }
    }

    #[test]
    fn raw_socket_option_failure_preserves_the_failed_operation() {
        let mut attempted = Vec::new();
        let error = configure_socket_options(IpAddr::V4(Ipv4Addr::LOCALHOST), |option| {
            attempted.push(option);
            if option == RawSocketOption::Ipv4Broadcast {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "fixture option failure",
                ))
            } else {
                Ok(())
            }
        })
        .expect_err("broadcast option failure is returned");

        assert_eq!(
            attempted,
            [
                RawSocketOption::Ipv4HeaderIncluded,
                RawSocketOption::Ipv4Broadcast,
            ]
        );
        assert_eq!(error.operation, "enabling IPv4 broadcast permission");
        assert_eq!(error.source.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn socket_address_scopes_only_ipv6_link_local_and_multicast_destinations() {
        let cases = [
            (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 7),
            (Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), 7),
            (Ipv6Addr::LOCALHOST, 0),
        ];

        for (address, expected_scope) in cases {
            let socket = socket_address(IpAddr::V6(address), 7)
                .as_socket()
                .expect("IP socket address");
            let SocketAddr::V6(socket) = socket else {
                panic!("expected IPv6 socket address")
            };
            assert_eq!(socket.scope_id(), expected_scope);
        }
    }

    #[test]
    fn raw_socket_errors_preserve_operation_context_and_stable_type() {
        let interface = InterfaceId {
            name: "fixture0".to_owned(),
            index: 4,
        };
        for (kind, expected) in [
            (io::ErrorKind::PermissionDenied, "privilege"),
            (io::ErrorKind::Unsupported, "unsupported"),
            (io::ErrorKind::NotFound, "device"),
            (io::ErrorKind::ConnectionRefused, "send"),
        ] {
            let error = map_raw_error(
                &interface,
                raw_error(
                    "binding fixture socket",
                    io::Error::new(kind, "fixture failure"),
                ),
            );
            assert!(error.to_string().contains("binding fixture socket"));
            let actual = match error {
                Error::Privilege { .. } => "privilege",
                Error::Unsupported { .. } => "unsupported",
                Error::Device { ref interface, .. } if interface == "fixture0" => "device",
                Error::Send { .. } => "send",
                other => panic!("unexpected mapping: {other:?}"),
            };
            assert_eq!(actual, expected);
        }
    }
}
