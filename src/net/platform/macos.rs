// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! macOS route and interface adapter backed by `getifaddrs(3)` and a routing
//! socket. Route lookup is passive: it does not perform neighbor discovery,
//! capture, or transmission.

#[cfg(feature = "native-route")]
use std::collections::BTreeMap;
#[cfg(feature = "native-route")]
use std::ffi::CStr;
#[cfg(feature = "native-route")]
use std::mem::{size_of, MaybeUninit};
#[cfg(feature = "native-route")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(feature = "native-route")]
use std::ptr;
#[cfg(feature = "native-route")]
use std::sync::atomic::{AtomicI32, Ordering};
#[cfg(feature = "native-route")]
use std::time::Duration;

#[cfg(feature = "native-route")]
use socket2::{Domain, Socket, Type};

#[cfg(feature = "native-route")]
use super::{find_interface, finish_route, interface_decision, NativeRouteSnapshot};
#[cfg(feature = "native-route")]
use crate::capture::LinkType;
#[cfg(feature = "native-route")]
use crate::net::{
    InterfaceAddress, InterfaceFlags, InterfaceId, InterfaceInfo, LinkCapability, MacAddress,
    NativeRouteError, RouteDecision, RouteSelectionReason,
};

#[cfg(feature = "native-route")]
static ROUTE_SEQUENCE: AtomicI32 = AtomicI32::new(1);

#[cfg(feature = "native-route")]
pub(super) fn interfaces() -> Result<Vec<InterfaceInfo>, NativeRouteError> {
    let mut head = ptr::null_mut();
    // SAFETY: `head` is a valid output pointer and a successful call owns a
    // linked list that remains valid until the matching `freeifaddrs` below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(last_os_error("getifaddrs"));
    }
    let guard = IfAddrsGuard(head);
    let mut by_index = BTreeMap::<u32, InterfaceInfo>::new();
    let mut current = guard.0;
    while !current.is_null() {
        // SAFETY: every node is part of the live list owned by `guard`.
        let entry = unsafe { &*current };
        if !entry.ifa_name.is_null() {
            // SAFETY: `ifa_name` is a NUL-terminated name owned by the list.
            let name = unsafe { CStr::from_ptr(entry.ifa_name) }
                .to_string_lossy()
                .into_owned();
            // SAFETY: the C string is valid for this call.
            let index = unsafe { libc::if_nametoindex(entry.ifa_name) };
            if index != 0 {
                let flags = entry.ifa_flags;
                let interface = by_index.entry(index).or_insert_with(|| InterfaceInfo {
                    id: InterfaceId {
                        name: name.clone(),
                        index,
                    },
                    description: None,
                    mac_address: None,
                    addresses: Vec::new(),
                    flags: interface_flags(flags),
                    mtu: None,
                    capability: LinkCapability::Layer3,
                    link_type: LinkType::RAW,
                });
                interface.flags = interface_flags(flags);

                if !entry.ifa_addr.is_null() {
                    // SAFETY: `ifa_addr` points to a sockaddr whose length is
                    // recorded in its first byte for the list lifetime.
                    let address = unsafe { &*entry.ifa_addr };
                    let length = usize::from(address.sa_len);
                    match i32::from(address.sa_family) {
                        libc::AF_INET | libc::AF_INET6 => {
                            // SAFETY: the live getifaddrs entry owns at least
                            // the declared sockaddr bytes for this iteration.
                            let bytes = unsafe {
                                std::slice::from_raw_parts(entry.ifa_addr.cast::<u8>(), length)
                            };
                            if let Some(ip) = sockaddr_ip(bytes) {
                                let prefix_length = if entry.ifa_netmask.is_null() {
                                    if ip.is_ipv4() {
                                        32
                                    } else {
                                        128
                                    }
                                } else {
                                    sockaddr_prefix(entry.ifa_netmask, ip.is_ipv4())
                                        .unwrap_or(if ip.is_ipv4() { 32 } else { 128 })
                                };
                                let assigned = InterfaceAddress {
                                    address: ip,
                                    prefix_length,
                                };
                                if !interface.addresses.contains(&assigned) {
                                    interface.addresses.push(assigned);
                                }
                            }
                        }
                        libc::AF_LINK => {
                            if let Some(mtu) = link_mtu(address.sa_family, entry.ifa_data) {
                                interface.mtu = Some(mtu);
                            }
                            interface.mac_address = link_address(entry.ifa_addr, length);
                            if interface.mac_address.is_some() && !interface.flags.loopback {
                                interface.capability = LinkCapability::Layer2And3;
                                interface.link_type = LinkType::ETHERNET;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        current = entry.ifa_next;
    }
    Ok(by_index.into_values().collect())
}

#[cfg(feature = "native-route")]
pub(super) fn route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
) -> Result<RouteDecision, NativeRouteError> {
    if preferred_source.is_some_and(|source| source.is_ipv4() != destination.is_ipv4()) {
        return Err(NativeRouteError::SourceFamilyMismatch {
            preferred_source: preferred_source.expect("checked source"),
            destination,
        });
    }

    let available = interfaces()?;
    let mut constrained_interface = interface_hint
        .map(|requested| find_interface(available.clone(), requested))
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

#[cfg(feature = "native-route")]
pub(super) fn interface_route(requested: &InterfaceId) -> Result<RouteDecision, NativeRouteError> {
    interface_decision(find_interface(interfaces()?, requested)?)
}

#[cfg(feature = "native-route")]
struct IfAddrsGuard(*mut libc::ifaddrs);

#[cfg(feature = "native-route")]
impl Drop for IfAddrsGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this is the list returned by `getifaddrs`, freed once.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
}

#[cfg(feature = "native-route")]
fn interface_flags(flags: libc::c_uint) -> InterfaceFlags {
    InterfaceFlags {
        up: flags & libc::IFF_UP as u32 != 0,
        broadcast: flags & libc::IFF_BROADCAST as u32 != 0,
        loopback: flags & libc::IFF_LOOPBACK as u32 != 0,
        point_to_point: flags & libc::IFF_POINTOPOINT as u32 != 0,
        multicast: flags & libc::IFF_MULTICAST as u32 != 0,
    }
}

#[cfg(feature = "native-route")]
fn link_mtu(family: libc::sa_family_t, data: *const libc::c_void) -> Option<u32> {
    if i32::from(family) != libc::AF_LINK || data.is_null() {
        return None;
    }
    // SAFETY: Darwin defines AF_LINK ifa_data as a live if_data object. The
    // family gate above is the audited conversion boundary.
    let data = unsafe { ptr::read_unaligned(data.cast::<libc::if_data>()) };
    (data.ifi_mtu != 0).then_some(data.ifi_mtu)
}

#[cfg(feature = "native-route")]
fn sockaddr_ip(bytes: &[u8]) -> Option<IpAddr> {
    // Darwin sockaddr starts with sa_len then sa_family. Never inspect the
    // family until both bytes are present.
    let family = *bytes.get(1)? as libc::sa_family_t;
    match i32::from(family) {
        libc::AF_INET if bytes.len() >= size_of::<libc::sockaddr_in>() => {
            // SAFETY: family and length establish a complete sockaddr_in.
            let value = unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<libc::sockaddr_in>()) };
            Some(IpAddr::V4(Ipv4Addr::from(
                value.sin_addr.s_addr.to_ne_bytes(),
            )))
        }
        libc::AF_INET6 if bytes.len() >= size_of::<libc::sockaddr_in6>() => {
            // SAFETY: family and length establish a complete sockaddr_in6.
            let value = unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<libc::sockaddr_in6>()) };
            Some(IpAddr::V6(Ipv6Addr::from(value.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

#[cfg(feature = "native-route")]
fn sockaddr_prefix(address: *const libc::sockaddr, ipv4: bool) -> Option<u8> {
    if address.is_null() {
        return None;
    }
    // SAFETY: a live sockaddr always contains its leading length byte, and
    // getifaddrs owns the declared record for this call.
    let length = usize::from(unsafe { *address.cast::<u8>() });
    let bytes = unsafe { std::slice::from_raw_parts(address.cast::<u8>(), length) };
    let ip = sockaddr_ip(bytes)?;
    match (ipv4, ip) {
        (true, IpAddr::V4(mask)) => Some(
            mask.octets()
                .iter()
                .map(|byte| byte.count_ones())
                .sum::<u32>() as u8,
        ),
        (false, IpAddr::V6(mask)) => Some(
            mask.octets()
                .iter()
                .map(|byte| byte.count_ones())
                .sum::<u32>() as u8,
        ),
        _ => None,
    }
}

#[cfg(feature = "native-route")]
fn link_address(address: *const libc::sockaddr, length: usize) -> Option<MacAddress> {
    if length < size_of::<libc::sockaddr_dl>() {
        return None;
    }
    // SAFETY: AF_LINK plus the checked length establishes the fixed portion.
    let link = unsafe { ptr::read_unaligned(address.cast::<libc::sockaddr_dl>()) };
    if link.sdl_alen != 6 {
        return None;
    }
    let data_offset = size_of::<libc::sockaddr_dl>() - link.sdl_data.len();
    let address_offset = data_offset.checked_add(usize::from(link.sdl_nlen))?;
    if address_offset.checked_add(6)? > length {
        return None;
    }
    let mut bytes = [0_u8; 6];
    // SAFETY: bounds above keep the six-byte copy within this sockaddr_dl.
    unsafe {
        ptr::copy_nonoverlapping(
            address.cast::<u8>().add(address_offset),
            bytes.as_mut_ptr(),
            6,
        )
    };
    Some(MacAddress(bytes))
}

#[cfg(feature = "native-route")]
struct RouteResponse {
    header: libc::rt_msghdr,
    gateway: Option<IpAddr>,
    selected_address: Option<IpAddr>,
}

#[cfg(feature = "native-route")]
fn query_route(
    destination: IpAddr,
    interface_index: Option<u32>,
) -> Result<RouteResponse, NativeRouteError> {
    let sequence = ROUTE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    // SAFETY: `getpid` has no preconditions.
    let pid = unsafe { libc::getpid() };
    let destination_address = encode_sockaddr(destination);
    let message_length = size_of::<libc::rt_msghdr>() + roundup(destination_address.len());
    if message_length > usize::from(u16::MAX) {
        return Err(NativeRouteError::InvalidResponse {
            message: "macOS route request exceeded the routing-socket limit".to_owned(),
        });
    }
    // SAFETY: all-zero is a valid baseline for this C message structure; all
    // discriminating and length fields are assigned immediately below.
    let mut header: libc::rt_msghdr = unsafe { std::mem::zeroed() };
    header.rtm_msglen = message_length as u16;
    header.rtm_version = libc::RTM_VERSION as u8;
    header.rtm_type = libc::RTM_GET as u8;
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
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
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
        if response_header.rtm_version != libc::RTM_VERSION as u8
            || response_header.rtm_type != libc::RTM_GET as u8
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

#[cfg(feature = "native-route")]
fn encode_sockaddr(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(address) => {
            // SAFETY: zero is valid for unused sockaddr fields.
            let mut value: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            value.sin_len = size_of::<libc::sockaddr_in>() as u8;
            value.sin_family = libc::AF_INET as libc::sa_family_t;
            value.sin_addr.s_addr = u32::from_ne_bytes(address.octets());
            structure_bytes(&value)
        }
        IpAddr::V6(address) => {
            // SAFETY: zero is valid for unused sockaddr fields.
            let mut value: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            value.sin6_len = size_of::<libc::sockaddr_in6>() as u8;
            value.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            value.sin6_addr.s6_addr = address.octets();
            structure_bytes(&value)
        }
    }
}

#[cfg(feature = "native-route")]
fn structure_bytes<T>(value: &T) -> Vec<u8> {
    // SAFETY: callers use plain C structs whose full initialized object
    // representation may be copied into an operating-system message.
    unsafe { std::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()).to_vec() }
}

#[cfg(feature = "native-route")]
fn parse_route_addresses(
    bytes: &[u8],
    mask: libc::c_int,
) -> Result<[Option<IpAddr>; libc::RTAX_MAX as usize], NativeRouteError> {
    let mut output = [None; libc::RTAX_MAX as usize];
    let address_slots = output.len();
    let mut offset = 0;
    for (index, slot) in output.iter_mut().enumerate() {
        if mask & (1 << index) == 0 {
            continue;
        }
        let Some(&length_byte) = bytes.get(offset) else {
            return Err(NativeRouteError::InvalidResponse {
                message: "macOS route response truncated its sockaddr list".to_owned(),
            });
        };
        let length = usize::from(length_byte);
        if length < 2 {
            return Err(NativeRouteError::InvalidResponse {
                message: format!(
                    "macOS route response sockaddr index {index} is too short for sa_family: length={length}"
                ),
            });
        }
        let stride = roundup(length);
        let Some(address_end) = offset.checked_add(length) else {
            return Err(NativeRouteError::InvalidResponse {
                message: "macOS route response sockaddr length overflowed".to_owned(),
            });
        };
        if address_end > bytes.len() {
            return Err(NativeRouteError::InvalidResponse {
                message: format!(
                    "macOS route response truncated sockaddr index {index}: offset={offset} length={length} bytes={}",
                    bytes.len()
                ),
            });
        }
        let padded_end = offset.checked_add(stride);
        let has_later_address = ((index + 1)..address_slots).any(|later| mask & (1 << later) != 0);
        let next_offset = match padded_end {
            Some(end) if end <= bytes.len() => end,
            // Darwin may omit only the otherwise-unused alignment trailer
            // after the final compact sockaddr. Its declared bytes remain
            // complete and there is no later address whose alignment could
            // become ambiguous.
            _ if !has_later_address && address_end == bytes.len() => address_end,
            _ => {
                return Err(NativeRouteError::InvalidResponse {
                    message: format!(
                        "macOS route response contained an invalid sockaddr at index {index}: offset={offset} length={length} stride={stride} bytes={}",
                        bytes.len()
                    ),
                })
            }
        };
        *slot = sockaddr_ip(&bytes[offset..address_end]);
        offset = next_offset;
    }
    Ok(output)
}

#[cfg(feature = "native-route")]
fn roundup(length: usize) -> usize {
    // Darwin's routing socket uses ROUNDUP32 for sockaddr records on both
    // x86_64 and arm64. This is deliberately independent of pointer/long
    // width; using c_long here skips four bytes after values such as the
    // 20-byte sockaddr_dl emitted for a directly connected route.
    let alignment = size_of::<u32>();
    if length == 0 {
        alignment
    } else {
        (length + alignment - 1) & !(alignment - 1)
    }
}

#[cfg(feature = "native-route")]
fn last_os_error(operation: &'static str) -> NativeRouteError {
    os_error(operation, std::io::Error::last_os_error())
}

#[cfg(feature = "native-route")]
fn os_error(operation: &'static str, error: impl std::fmt::Display) -> NativeRouteError {
    NativeRouteError::OperatingSystem {
        operation,
        message: error.to_string(),
    }
}

#[cfg(all(test, feature = "native-route"))]
mod tests {
    use super::*;
    use crate::net::RouteProvider;

    #[test]
    fn native_macos_provider_finds_loopback_routes_and_interfaces() {
        let interfaces = interfaces().unwrap();
        assert!(interfaces.iter().any(|interface| interface.flags.loopback));

        let provider = crate::net::SystemRouteProvider;
        let ipv4 = provider
            .lookup(IpAddr::V4(Ipv4Addr::LOCALHOST), None)
            .unwrap();
        assert_eq!(ipv4.selection_reason, RouteSelectionReason::Local);
        assert!(ipv4.selected_address.is_some_and(|source| source.is_ipv4()));

        let ipv6 = provider
            .lookup(IpAddr::V6(Ipv6Addr::LOCALHOST), None)
            .unwrap();
        assert_eq!(ipv6.selection_reason, RouteSelectionReason::Local);
        assert!(ipv6.selected_address.is_some_and(|source| source.is_ipv6()));
    }

    #[test]
    fn route_address_parser_accepts_only_an_unpadded_final_compact_sockaddr() {
        let mut destination = encode_sockaddr(IpAddr::V4(Ipv4Addr::new(10, 50, 1, 0)));
        let compact_mask = [7_u8, 0, 0xff, 0xff, 0xff, 0, 0];
        destination.extend_from_slice(&compact_mask);
        let addresses =
            parse_route_addresses(&destination, libc::RTA_DST | libc::RTA_NETMASK).unwrap();
        assert_eq!(
            addresses[libc::RTAX_DST as usize],
            Some(IpAddr::V4(Ipv4Addr::new(10, 50, 1, 0)))
        );

        let error =
            parse_route_addresses(&compact_mask, libc::RTA_NETMASK | libc::RTA_IFA).unwrap_err();
        assert!(error.to_string().contains("invalid sockaddr"));
    }

    #[test]
    fn route_address_parser_uses_darwin_32_bit_sockaddr_alignment() {
        let mut message = encode_sockaddr(IpAddr::V4(Ipv4Addr::new(10, 50, 1, 0)));
        let mut gateway = [0_u8; 20];
        gateway[0] = gateway.len() as u8;
        gateway[1] = libc::AF_LINK as u8;
        message.extend_from_slice(&gateway);
        message.extend_from_slice(&[7_u8, 0, 0xff, 0xff, 0xff, 0, 0]);

        let addresses = parse_route_addresses(
            &message,
            libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK,
        )
        .unwrap();
        assert_eq!(
            addresses[libc::RTAX_DST as usize],
            Some(IpAddr::V4(Ipv4Addr::new(10, 50, 1, 0)))
        );
        assert_eq!(roundup(20), 20);
        assert_eq!(roundup(7), 8);
    }

    #[test]
    fn sockaddr_parser_checks_two_byte_family_and_exact_family_sizes() {
        assert_eq!(sockaddr_ip(&[]), None);
        assert_eq!(sockaddr_ip(&[1]), None);
        assert_eq!(sockaddr_ip(&[2, 0xff]), None);

        for address in [
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6("2001:db8::1".parse().unwrap()),
        ] {
            let encoded = encode_sockaddr(address);
            assert_eq!(sockaddr_ip(&encoded), Some(address));
            assert_eq!(sockaddr_ip(&encoded[..encoded.len() - 1]), None);
        }

        for bytes in [vec![0], vec![1]] {
            assert!(parse_route_addresses(&bytes, libc::RTA_DST).is_err());
        }
        assert!(parse_route_addresses(&[2, 0xff, 0, 0], libc::RTA_DST).is_ok());
    }

    #[test]
    fn interface_mtu_data_is_interpreted_only_for_af_link() {
        let differently_typed = 0x5a_u8;
        assert_eq!(
            link_mtu(
                libc::AF_INET as libc::sa_family_t,
                (&differently_typed as *const u8).cast(),
            ),
            None
        );

        // SAFETY: all-zero is a valid baseline for the synthetic C record.
        let mut data: libc::if_data = unsafe { std::mem::zeroed() };
        data.ifi_mtu = 1500;
        assert_eq!(
            link_mtu(
                libc::AF_LINK as libc::sa_family_t,
                (&data as *const libc::if_data).cast(),
            ),
            Some(1500)
        );
    }
}
