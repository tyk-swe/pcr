// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! macOS routing socket query and passive route lookup.

#![allow(unsafe_code)]

use std::mem::{MaybeUninit, offset_of, size_of};
use std::net::IpAddr;
use std::ptr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Instant;

use packetcraftr_core::budget::Deadline;
use socket2::{Domain, Socket, Type};

use super::enumeration::interfaces;
use super::parser::{parse_route_addresses, roundup};
use crate::deadline::{POLL_INTERVAL, expires_at, remaining_before};
use crate::platform::route::{constrain_by_preferred_source, find_interface, os_error};
use crate::route::normalize::{NativeRouteSnapshot, finish_route, interface_decision};
use crate::{
    interface::Id as InterfaceId,
    route::{Decision, SelectionReason, SystemError},
};

static ROUTE_SEQUENCE: AtomicI32 = AtomicI32::new(1);

/// Unrelated routing-socket messages a query skips before giving up.
const MAX_UNMATCHED_MESSAGES: usize = 64;

/// Runs on the worker pool; reads are sliced by the deadline so a cancelled
/// caller's work stops promptly.
pub(super) fn route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
    deadline: &Deadline,
) -> Result<Decision, SystemError> {
    let available = interfaces()?;
    let requested = interface_hint
        .map(|requested| find_interface(&available, requested))
        .transpose()?;
    let constrained_interface =
        constrain_by_preferred_source(&available, interface_hint, requested, preferred_source)?;

    let response = query_route(
        destination,
        constrained_interface
            .as_ref()
            .map(|interface| interface.id.index),
        deadline,
    )?;
    let output_index = u32::from(response.header.rtm_index);
    let local_addresses = available
        .iter()
        .flat_map(|interface| interface.addresses.iter().map(|assigned| assigned.address))
        .collect();
    let interface = available
        .into_iter()
        .find(|interface| interface.id.index == output_index)
        .ok_or_else(|| SystemError::InterfaceNotFound {
            name: constrained_interface.as_ref().map_or_else(
                || format!("index-{output_index}"),
                |interface| interface.id.name.clone(),
            ),
            index: output_index,
        })?;
    let local = response.header.rtm_flags & libc::RTF_LOCAL != 0;
    let broadcast = response.header.rtm_flags & libc::RTF_BROADCAST != 0;
    let next_hop = response.gateway.filter(|address| !address.is_unspecified());
    finish_route(
        destination,
        constrained_interface
            .as_ref()
            .map(|interface| &interface.id),
        preferred_source,
        NativeRouteSnapshot {
            interface,
            local_addresses,
            selected_source: response.selected_source,
            next_hop,
            route_mtu: (response.header.rtm_rmx.rmx_mtu != 0)
                .then_some(response.header.rtm_rmx.rmx_mtu),
            selection_reason: if local {
                SelectionReason::Local
            } else if broadcast {
                SelectionReason::Broadcast
            } else if next_hop.is_some() {
                SelectionReason::Gateway
            } else {
                SelectionReason::OnLink
            },
        },
    )
}

/// `getifaddrs(3)` answers from the kernel without waiting, so the caller's
/// deadline has already been checked by the time this runs.
pub(in crate::platform) fn interface_route(
    requested: &InterfaceId,
    _deadline: &Deadline,
) -> Result<Decision, SystemError> {
    interface_decision(find_interface(&interfaces()?, requested)?)
}

struct RouteResponse {
    header: libc::rt_msghdr,
    gateway: Option<IpAddr>,
    selected_source: Option<IpAddr>,
}

struct RouteRequest {
    bytes: Vec<u8>,
    version: u8,
    message_type: u8,
    pid: libc::pid_t,
    sequence: i32,
}

fn query_route(
    destination: IpAddr,
    interface_index: Option<u32>,
    caller: &Deadline,
) -> Result<RouteResponse, SystemError> {
    let deadline = expires_at(caller).map_err(|interrupted| {
        SystemError::interrupted(interrupted, "querying the macOS routing socket")
    })?;
    let request = build_route_request(destination, interface_index)?;
    let socket = send_route_request(&request, destination, deadline)?;
    read_route_response(&socket, destination, caller, deadline, &request)
}

/// The caller's deadline expired during `operation`.
fn route_timeout(operation: &'static str) -> SystemError {
    SystemError::DeadlineExceeded { operation }
}

/// Whether a socket call ended because its timeout elapsed.
fn timed_out(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

fn build_route_request(
    destination: IpAddr,
    interface_index: Option<u32>,
) -> Result<RouteRequest, SystemError> {
    let sequence = ROUTE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    // SAFETY: `getpid` has no preconditions.
    let pid = unsafe { libc::getpid() };
    let destination_address = encode_sockaddr(destination)?;
    let message_length = size_of::<libc::rt_msghdr>()
        .checked_add(roundup(destination_address.len()))
        .ok_or_else(|| SystemError::InvalidResponse {
            message: "macOS route request exceeded the routing-socket limit".to_owned(),
        })?;
    let wire_message_length =
        u16::try_from(message_length).map_err(|_| SystemError::InvalidResponse {
            message: "macOS route request exceeded the routing-socket limit".to_owned(),
        })?;
    let version = u8::try_from(libc::RTM_VERSION).map_err(|_| SystemError::InvalidResponse {
        message: "macOS RTM_VERSION does not fit its routing-socket field".to_owned(),
    })?;
    let message_type = u8::try_from(libc::RTM_GET).map_err(|_| SystemError::InvalidResponse {
        message: "macOS RTM_GET does not fit its routing-socket field".to_owned(),
    })?;
    // SAFETY: all-zero is a valid baseline for this C message structure; all
    // discriminating and length fields are assigned immediately below.
    let mut header: libc::rt_msghdr = unsafe { std::mem::zeroed() };
    header.rtm_msglen = wire_message_length;
    header.rtm_version = version;
    header.rtm_type = message_type;
    header.rtm_flags = libc::RTF_UP | libc::RTF_HOST;
    header.rtm_addrs = libc::RTA_DST;
    header.rtm_pid = pid;
    header.rtm_seq = sequence;
    if let Some(index) = interface_index {
        header.rtm_index = u16::try_from(index).map_err(|_| SystemError::InvalidResponse {
            message: format!("macOS interface index {index} exceeds routing-socket width"),
        })?;
        header.rtm_flags |= libc::RTF_IFSCOPE;
    }

    let mut bytes = vec![0_u8; message_length];
    // SAFETY: the request has room for the header and the encoded sockaddr.
    unsafe {
        ptr::write_unaligned(bytes.as_mut_ptr().cast::<libc::rt_msghdr>(), header);
        ptr::copy_nonoverlapping(
            destination_address.as_ptr(),
            bytes.as_mut_ptr().add(size_of::<libc::rt_msghdr>()),
            destination_address.len(),
        );
    }

    Ok(RouteRequest {
        bytes,
        version,
        message_type,
        pid,
        sequence,
    })
}

fn send_route_request(
    request: &RouteRequest,
    destination: IpAddr,
    deadline: Instant,
) -> Result<Socket, SystemError> {
    let socket = Socket::new(Domain::from(libc::AF_ROUTE), Type::RAW, None)
        .map_err(|error| os_error("open routing socket", error))?;
    let remaining =
        remaining_before(deadline).ok_or_else(|| route_timeout("writing the RTM_GET request"))?;
    socket
        .set_write_timeout(Some(remaining))
        .map_err(|error| os_error("set routing-socket timeout", error))?;
    let sent = socket
        .send(&request.bytes)
        .map_err(|error| route_write_error(destination, error))?;
    if sent != request.bytes.len() {
        return Err(SystemError::InvalidResponse {
            message: format!(
                "macOS routing socket accepted {sent} of {} bytes",
                request.bytes.len()
            ),
        });
    }

    Ok(socket)
}

/// Darwin fails the RTM_GET write itself when the lookup finds no route
/// ("writing to routing socket: not in table"), so the no-route errnos an
/// echoed `rtm_errno` would carry mean the same thing here.
fn route_write_error(destination: IpAddr, error: std::io::Error) -> SystemError {
    if matches!(error.raw_os_error(), Some(libc::ESRCH | libc::ENETUNREACH)) {
        return SystemError::RouteNotFound { destination };
    }
    if timed_out(&error) {
        return route_timeout("writing the RTM_GET request");
    }
    os_error("write RTM_GET", error)
}

fn read_route_response(
    socket: &Socket,
    destination: IpAddr,
    caller: &Deadline,
    deadline: Instant,
    request: &RouteRequest,
) -> Result<RouteResponse, SystemError> {
    let mut unmatched = 0;
    while unmatched < MAX_UNMATCHED_MESSAGES {
        let remaining = remaining_before(deadline)
            .ok_or_else(|| route_timeout("reading the RTM_GET response"))?;
        // Reads wait in slices so a cancelled caller is noticed promptly.
        socket
            .set_read_timeout(Some(remaining.min(POLL_INTERVAL)))
            .map_err(|error| os_error("set routing-socket timeout", error))?;
        let mut response = [MaybeUninit::<u8>::uninit(); 4096];
        let length = match socket.recv(&mut response) {
            Ok(length) => length,
            Err(error) if timed_out(&error) => {
                caller.check_cancelled()?;
                continue;
            }
            Err(error) => return Err(os_error("read RTM_GET", error)),
        };
        if length < size_of::<libc::rt_msghdr>() {
            unmatched += 1;
            continue;
        }
        // SAFETY: `recv` initialized the returned prefix; the slice is limited
        // to exactly that prefix before parsing.
        let bytes = unsafe { std::slice::from_raw_parts(response.as_ptr().cast::<u8>(), length) };
        // SAFETY: the checked prefix contains a complete header; unaligned
        // reads are used because a byte buffer has no C-struct alignment.
        let response_header =
            unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<libc::rt_msghdr>()) };
        if response_header.rtm_version != request.version
            || response_header.rtm_type != request.message_type
            || response_header.rtm_pid != request.pid
            || response_header.rtm_seq != request.sequence
        {
            unmatched += 1;
            continue;
        }
        let declared = usize::from(response_header.rtm_msglen);
        if declared < size_of::<libc::rt_msghdr>() || declared > bytes.len() {
            return Err(SystemError::InvalidResponse {
                message: "macOS route response had an invalid message length".to_owned(),
            });
        }
        if response_header.rtm_errno != 0 {
            if matches!(response_header.rtm_errno, libc::ESRCH | libc::ENETUNREACH) {
                return Err(SystemError::RouteNotFound { destination });
            }
            return Err(os_error(
                "RTM_GET",
                std::io::Error::from_raw_os_error(response_header.rtm_errno),
            ));
        }
        let payload = bytes
            .get(size_of::<libc::rt_msghdr>()..declared)
            .ok_or_else(|| SystemError::InvalidResponse {
                message: "macOS route response had an invalid message length".to_owned(),
            })?;
        let addresses = parse_route_addresses(payload, response_header.rtm_addrs)?;
        return Ok(RouteResponse {
            header: response_header,
            gateway: addresses
                .get(libc::RTAX_GATEWAY as usize)
                .copied()
                .flatten(),
            selected_source: addresses.get(libc::RTAX_IFA as usize).copied().flatten(),
        });
    }
    Err(SystemError::InvalidResponse {
        message: "macOS routing socket returned no matching RTM_GET response".to_owned(),
    })
}

/// Encodes a destination as the Darwin routing-socket `sockaddr`.
///
/// Each field is written at the offset `libc` declares for this target's own
/// structure, and every byte the C structure does not name stays zero.
fn encode_sockaddr(address: IpAddr) -> Result<Vec<u8>, SystemError> {
    match address {
        IpAddr::V4(address) => {
            let length = u8::try_from(size_of::<libc::sockaddr_in>()).map_err(|_| {
                SystemError::InvalidResponse {
                    message: "macOS sockaddr_in length does not fit sin_len".to_owned(),
                }
            })?;
            let family = libc::sa_family_t::try_from(libc::AF_INET).map_err(|_| {
                SystemError::InvalidResponse {
                    message: "macOS AF_INET does not fit sa_family_t".to_owned(),
                }
            })?;
            let mut bytes = vec![0_u8; size_of::<libc::sockaddr_in>()];
            write_sockaddr_field(
                &mut bytes,
                offset_of!(libc::sockaddr_in, sin_len),
                &length.to_ne_bytes(),
            )?;
            write_sockaddr_field(
                &mut bytes,
                offset_of!(libc::sockaddr_in, sin_family),
                &family.to_ne_bytes(),
            )?;
            write_sockaddr_field(
                &mut bytes,
                offset_of!(libc::sockaddr_in, sin_addr),
                &address.octets(),
            )?;
            Ok(bytes)
        }
        IpAddr::V6(address) => {
            let length = u8::try_from(size_of::<libc::sockaddr_in6>()).map_err(|_| {
                SystemError::InvalidResponse {
                    message: "macOS sockaddr_in6 length does not fit sin6_len".to_owned(),
                }
            })?;
            let family = libc::sa_family_t::try_from(libc::AF_INET6).map_err(|_| {
                SystemError::InvalidResponse {
                    message: "macOS AF_INET6 does not fit sa_family_t".to_owned(),
                }
            })?;
            let mut bytes = vec![0_u8; size_of::<libc::sockaddr_in6>()];
            write_sockaddr_field(
                &mut bytes,
                offset_of!(libc::sockaddr_in6, sin6_len),
                &length.to_ne_bytes(),
            )?;
            write_sockaddr_field(
                &mut bytes,
                offset_of!(libc::sockaddr_in6, sin6_family),
                &family.to_ne_bytes(),
            )?;
            write_sockaddr_field(
                &mut bytes,
                offset_of!(libc::sockaddr_in6, sin6_addr),
                &address.octets(),
            )?;
            Ok(bytes)
        }
    }
}

fn write_sockaddr_field(bytes: &mut [u8], offset: usize, value: &[u8]) -> Result<(), SystemError> {
    offset
        .checked_add(value.len())
        .and_then(|end| bytes.get_mut(offset..end))
        .ok_or_else(|| SystemError::InvalidResponse {
            message: "macOS sockaddr field does not fit its own structure".to_owned(),
        })?
        .copy_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {

    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn a_route_write_refused_for_lack_of_a_route_reports_route_not_found() {
        let destination = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        for errno in [libc::ESRCH, libc::ENETUNREACH] {
            assert!(matches!(
                route_write_error(destination, std::io::Error::from_raw_os_error(errno)),
                SystemError::RouteNotFound { destination: actual } if actual == destination
            ));
        }
        assert!(matches!(
            route_write_error(destination, std::io::Error::from_raw_os_error(libc::EACCES)),
            SystemError::OperatingSystem {
                operation: "write RTM_GET",
                ..
            }
        ));
    }

    #[test]
    fn sockaddr_encoding_fills_exactly_the_darwin_length_family_and_address_fields() {
        let encoded =
            encode_sockaddr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))).expect("IPv4 sockaddr");
        assert_eq!(encoded.len(), size_of::<libc::sockaddr_in>());
        assert_eq!(
            usize::from(encoded[offset_of!(libc::sockaddr_in, sin_len)]),
            size_of::<libc::sockaddr_in>()
        );
        assert_eq!(
            i32::from(encoded[offset_of!(libc::sockaddr_in, sin_family)]),
            libc::AF_INET
        );
        let address = offset_of!(libc::sockaddr_in, sin_addr);
        assert_eq!(&encoded[address..address + 4], &[192, 0, 2, 1]);
        let port = offset_of!(libc::sockaddr_in, sin_port);
        assert_eq!(&encoded[port..port + 2], &[0, 0]);

        let address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let encoded = encode_sockaddr(IpAddr::V6(address)).expect("IPv6 sockaddr");
        assert_eq!(encoded.len(), size_of::<libc::sockaddr_in6>());
        assert_eq!(
            usize::from(encoded[offset_of!(libc::sockaddr_in6, sin6_len)]),
            size_of::<libc::sockaddr_in6>()
        );
        assert_eq!(
            i32::from(encoded[offset_of!(libc::sockaddr_in6, sin6_family)]),
            libc::AF_INET6
        );
        let start = offset_of!(libc::sockaddr_in6, sin6_addr);
        assert_eq!(&encoded[start..start + 16], &address.octets());
        let scope = offset_of!(libc::sockaddr_in6, sin6_scope_id);
        assert_eq!(&encoded[scope..scope + 4], &[0, 0, 0, 0]);
    }

    #[test]
    fn sockaddr_field_writes_refuse_to_run_past_their_structure() {
        let mut bytes = [0_u8; 4];
        assert!(write_sockaddr_field(&mut bytes, 3, &[1, 2]).is_err());
        assert!(write_sockaddr_field(&mut bytes, usize::MAX, &[1]).is_err());
        assert_eq!(bytes, [0; 4]);
    }
}
