// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! macOS routing socket query and passive route lookup.

#![allow(unsafe_code)]

use std::mem::{MaybeUninit, size_of};
use std::net::IpAddr;
use std::ptr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use socket2::{Domain, Socket, Type};

use super::enumeration::{interfaces, os_error};
use super::parser::{parse_route_addresses, roundup};
use crate::{
    platform::{
        NativeRouteSnapshot, finish_route, interface_decision, validate_preferred_source_family,
    },
    route::{InterfaceId, NativeRouteError, RouteDecision, RouteSelectionReason, find_interface},
};

static ROUTE_SEQUENCE: AtomicI32 = AtomicI32::new(1);

pub(in crate::platform) fn route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
) -> Result<RouteDecision, NativeRouteError> {
    validate_preferred_source_family(destination, preferred_source)?;

    let available = interfaces()?;
    let mut constrained_interface = interface_hint
        .map(|requested| find_interface(&available, requested))
        .transpose()?;
    if let Some(source) = preferred_source {
        let source_interface = available
            .iter()
            .find(|interface| {
                interface
                    .addresses
                    .iter()
                    .any(|assigned| assigned.address == source)
            })
            .cloned()
            .ok_or_else(|| NativeRouteError::SourceUnavailable {
                preferred_source: source,
                interface: interface_hint
                    .map_or_else(|| "any interface".to_owned(), |hint| hint.name.clone()),
            })?;
        if let Some(requested) = &constrained_interface {
            if requested.id != source_interface.id {
                return Err(NativeRouteError::SourceUnavailable {
                    preferred_source: source,
                    interface: requested.id.name.clone(),
                });
            }
        } else {
            constrained_interface = Some(source_interface);
        }
    }

    let response = query_route(
        destination,
        constrained_interface
            .as_ref()
            .map(|interface| interface.id.index),
    )?;
    let output_index = u32::from(response.header.rtm_index);
    let interface = available
        .into_iter()
        .find(|interface| interface.id.index == output_index)
        .ok_or_else(|| NativeRouteError::InterfaceNotFound {
            name: constrained_interface.as_ref().map_or_else(
                || format!("index-{output_index}"),
                |interface| interface.id.name.clone(),
            ),
            index: output_index,
        })?;
    let local = response.header.rtm_flags & libc::RTF_LOCAL != 0;
    let next_hop = response.gateway.filter(|address| !address.is_unspecified());
    finish_route(
        destination,
        constrained_interface
            .as_ref()
            .map(|interface| &interface.id),
        preferred_source,
        NativeRouteSnapshot {
            interface,
            selected_address: response.selected_address,
            next_hop,
            route_mtu: (response.header.rtm_rmx.rmx_mtu != 0)
                .then_some(response.header.rtm_rmx.rmx_mtu),
            selection_reason: if local {
                RouteSelectionReason::Local
            } else if next_hop.is_some() {
                RouteSelectionReason::Gateway
            } else {
                RouteSelectionReason::OnLink
            },
        },
    )
}

pub(in crate::platform) fn interface_route(
    requested: &InterfaceId,
) -> Result<RouteDecision, NativeRouteError> {
    interface_decision(find_interface(&interfaces()?, requested)?)
}

struct RouteResponse {
    header: libc::rt_msghdr,
    gateway: Option<IpAddr>,
    selected_address: Option<IpAddr>,
}

fn query_route(
    destination: IpAddr,
    interface_index: Option<u32>,
) -> Result<RouteResponse, NativeRouteError> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(2))
        .expect("the bounded routing-socket timeout must fit Instant");
    let sequence = ROUTE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    // SAFETY: `getpid` has no preconditions.
    let pid = unsafe { libc::getpid() };
    let destination_address = encode_sockaddr(destination)?;
    let message_length = size_of::<libc::rt_msghdr>() + roundup(destination_address.len());
    let wire_message_length =
        u16::try_from(message_length).map_err(|_| NativeRouteError::InvalidResponse {
            message: "macOS route request exceeded the routing-socket limit".to_owned(),
        })?;
    let route_version =
        u8::try_from(libc::RTM_VERSION).map_err(|_| NativeRouteError::InvalidResponse {
            message: "macOS RTM_VERSION does not fit its routing-socket field".to_owned(),
        })?;
    let route_type =
        u8::try_from(libc::RTM_GET).map_err(|_| NativeRouteError::InvalidResponse {
            message: "macOS RTM_GET does not fit its routing-socket field".to_owned(),
        })?;
    // SAFETY: all-zero is a valid baseline for this C message structure; all
    // discriminating and length fields are assigned immediately below.
    let mut header: libc::rt_msghdr = unsafe { std::mem::zeroed() };
    header.rtm_msglen = wire_message_length;
    header.rtm_version = route_version;
    header.rtm_type = route_type;
    header.rtm_flags = libc::RTF_UP | libc::RTF_HOST;
    header.rtm_addrs = libc::RTA_DST;
    header.rtm_pid = pid;
    header.rtm_seq = sequence;
    if let Some(index) = interface_index {
        header.rtm_index = u16::try_from(index).map_err(|_| NativeRouteError::InvalidResponse {
            message: format!("macOS interface index {index} exceeds routing-socket width"),
        })?;
        header.rtm_flags |= libc::RTF_IFSCOPE;
    }

    let mut request = vec![0_u8; message_length];
    // SAFETY: the request has room for the header and the encoded sockaddr.
    unsafe {
        ptr::write_unaligned(request.as_mut_ptr().cast::<libc::rt_msghdr>(), header);
        ptr::copy_nonoverlapping(
            destination_address.as_ptr(),
            request.as_mut_ptr().add(size_of::<libc::rt_msghdr>()),
            destination_address.len(),
        );
    }

    let socket = Socket::new(Domain::from(libc::AF_ROUTE), Type::RAW, None)
        .map_err(|error| os_error("open routing socket", error))?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| NativeRouteError::OperatingSystem {
            operation: "write RTM_GET",
            message: "macOS routing-socket request deadline expired".to_owned(),
        })?;
    socket
        .set_write_timeout(Some(remaining))
        .map_err(|error| os_error("set routing-socket timeout", error))?;
    let sent = socket
        .send(&request)
        .map_err(|error| os_error("write RTM_GET", error))?;
    if sent != request.len() {
        return Err(NativeRouteError::InvalidResponse {
            message: format!(
                "macOS routing socket accepted {sent} of {} bytes",
                request.len()
            ),
        });
    }

    for _ in 0..64 {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| NativeRouteError::OperatingSystem {
                operation: "read RTM_GET",
                message: "macOS routing-socket response deadline expired".to_owned(),
            })?;
        socket
            .set_read_timeout(Some(remaining))
            .map_err(|error| os_error("set routing-socket timeout", error))?;
        let mut response = [MaybeUninit::<u8>::uninit(); 4096];
        let length = socket
            .recv(&mut response)
            .map_err(|error| os_error("read RTM_GET", error))?;
        if length < size_of::<libc::rt_msghdr>() {
            continue;
        }
        // SAFETY: `recv` initialized the returned prefix; the slice is limited
        // to exactly that prefix before parsing.
        let bytes = unsafe { std::slice::from_raw_parts(response.as_ptr().cast::<u8>(), length) };
        // SAFETY: the checked prefix contains a complete header; unaligned
        // reads are used because a byte buffer has no C-struct alignment.
        let response_header =
            unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<libc::rt_msghdr>()) };
        if response_header.rtm_version != route_version
            || response_header.rtm_type != route_type
            || response_header.rtm_pid != pid
            || response_header.rtm_seq != sequence
        {
            continue;
        }
        let declared = usize::from(response_header.rtm_msglen);
        if declared < size_of::<libc::rt_msghdr>() || declared > bytes.len() {
            return Err(NativeRouteError::InvalidResponse {
                message: "macOS route response had an invalid message length".to_owned(),
            });
        }
        if response_header.rtm_errno != 0 {
            if matches!(response_header.rtm_errno, libc::ESRCH | libc::ENETUNREACH) {
                return Err(NativeRouteError::RouteNotFound { destination });
            }
            return Err(os_error(
                "RTM_GET",
                std::io::Error::from_raw_os_error(response_header.rtm_errno),
            ));
        }
        let addresses = parse_route_addresses(
            &bytes[size_of::<libc::rt_msghdr>()..declared],
            response_header.rtm_addrs,
        )?;
        return Ok(RouteResponse {
            header: response_header,
            gateway: addresses[libc::RTAX_GATEWAY as usize],
            selected_address: addresses[libc::RTAX_IFA as usize],
        });
    }
    Err(NativeRouteError::InvalidResponse {
        message: "macOS routing socket returned no matching RTM_GET response".to_owned(),
    })
}

pub(super) fn encode_sockaddr(address: IpAddr) -> Result<Vec<u8>, NativeRouteError> {
    match address {
        IpAddr::V4(address) => {
            // SAFETY: zero is valid for unused sockaddr fields.
            let mut value: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            value.sin_len = u8::try_from(size_of::<libc::sockaddr_in>()).map_err(|_| {
                NativeRouteError::InvalidResponse {
                    message: "macOS sockaddr_in length does not fit sin_len".to_owned(),
                }
            })?;
            value.sin_family = libc::sa_family_t::try_from(libc::AF_INET).map_err(|_| {
                NativeRouteError::InvalidResponse {
                    message: "macOS AF_INET does not fit sa_family_t".to_owned(),
                }
            })?;
            value.sin_addr.s_addr = u32::from_ne_bytes(address.octets());
            Ok(structure_bytes(&value))
        }
        IpAddr::V6(address) => {
            // SAFETY: zero is valid for unused sockaddr fields.
            let mut value: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            value.sin6_len = u8::try_from(size_of::<libc::sockaddr_in6>()).map_err(|_| {
                NativeRouteError::InvalidResponse {
                    message: "macOS sockaddr_in6 length does not fit sin6_len".to_owned(),
                }
            })?;
            value.sin6_family = libc::sa_family_t::try_from(libc::AF_INET6).map_err(|_| {
                NativeRouteError::InvalidResponse {
                    message: "macOS AF_INET6 does not fit sa_family_t".to_owned(),
                }
            })?;
            value.sin6_addr.s6_addr = address.octets();
            Ok(structure_bytes(&value))
        }
    }
}

fn structure_bytes<T>(value: &T) -> Vec<u8> {
    // SAFETY: callers use plain C structs whose full initialized object
    // representation may be copied into an operating-system message.
    unsafe { std::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()).to_vec() }
}
