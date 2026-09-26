// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The native capture path behind [`SystemProvider`](super::SystemProvider):
//! every request check, the interface identity check, and the BPF netmask
//! happen here before the selected backend opens its source.

use packetcraftr_core::budget::Deadline;

use super::{Request, Session, TimestampType};
use crate::{Error, interface::Id as InterfaceId};

/// Opening and activating a native source does not wait on the network, so
/// the caller's deadline is checked once, before any native work starts.
#[cfg(native_layer2)]
pub(super) fn open(request: &Request, deadline: &Deadline) -> Result<Box<dyn Session>, Error> {
    request
        .limits
        .validate()
        .and_then(|()| request.native.validate(&request.limits))?;
    let limits = request.limits;
    if let Some(filter) = request.filter.as_deref() {
        super::filter::validate(&request.interface, filter)?;
    }
    crate::deadline::remaining(deadline)
        .map_err(|interrupted| Error::interrupted(interrupted, "arming capture"))?;
    let interface = crate::platform::current_interface(&request.interface, deadline)?;
    let parts = crate::platform::open_capture(
        &interface.id,
        limits,
        request.filter.as_deref(),
        netmask(&interface),
        request.promiscuous,
        &request.native,
    )?;
    Ok(Box::new(super::live::NativeCaptureSession::spawn(
        parts, limits,
    )?))
}

#[cfg(not(native_layer2))]
pub(super) fn open(_request: &Request, _deadline: &Deadline) -> Result<Box<dyn Session>, Error> {
    Err(crate::platform::unsupported(
        cfg!(feature = "native-layer2"),
        "native-layer2",
        "packet capture",
    ))
}

#[cfg(native_layer2)]
pub(super) fn timestamp_types(
    interface: &InterfaceId,
    deadline: &Deadline,
) -> Result<Vec<TimestampType>, Error> {
    let interface = crate::platform::current_interface(interface, deadline)?;
    crate::platform::timestamp_types(&interface.id)
}

#[cfg(not(native_layer2))]
pub(super) fn timestamp_types(
    _interface: &InterfaceId,
    _deadline: &Deadline,
) -> Result<Vec<TimestampType>, Error> {
    Err(crate::platform::unsupported(
        cfg!(feature = "native-layer2"),
        "native-layer2",
        "timestamp type discovery",
    ))
}

#[cfg(native_layer2)]
fn netmask(interface: &crate::interface::Info) -> Option<u32> {
    let assigned = interface
        .addresses
        .iter()
        .find(|assigned| assigned.address.is_ipv4())?;
    let shift = u32::BITS.checked_sub(u32::from(assigned.prefix_length))?;
    // pcap_compile compares the mask with host-order BPF word loads, so a /24
    // is 0xffffff00 on every target, not its network-order bytes.
    Some(u32::MAX.checked_shl(shift).unwrap_or(0))
}

#[cfg(all(test, native_layer2))]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use packetcraftr_core::frame::LinkType;

    use super::*;
    use crate::{interface, link::Capability};

    #[test]
    fn capture_netmask_uses_the_first_ipv4_assignment() {
        let interface = interface::Info {
            id: InterfaceId {
                name: "fixture0".to_owned(),
                index: 7,
            },
            description: None,
            mac_address: None,
            addresses: vec![
                interface::Address {
                    address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    prefix_length: 8,
                },
                interface::Address {
                    address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                    prefix_length: 24,
                },
            ],
            flags: interface::Flags::default(),
            mtu: None,
            capability: Capability::Layer2AndLayer3,
            link_type: LinkType::ETHERNET,
        };

        assert_eq!(netmask(&interface), Some(0xff00_0000));

        let mut ipv6_only = interface;
        ipv6_only.addresses = vec![interface::Address {
            address: IpAddr::V6(Ipv6Addr::LOCALHOST),
            prefix_length: 128,
        }];
        assert_eq!(netmask(&ipv6_only), None);
    }
}
