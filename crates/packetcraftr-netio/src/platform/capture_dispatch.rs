// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native capture capability dispatch.

#![forbid(unsafe_code)]

#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos", windows)
))]
use crate::interface;
use crate::{Error, capture};

#[cfg(all(feature = "native-layer2", windows))]
use super::npcap as capture_backend;
#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos")
))]
use super::pcap_backend as capture_backend;

#[cfg(feature = "native-layer2")]
pub(crate) fn system_capture(
    request: &capture::Request,
) -> Result<Box<dyn capture::Session>, Error> {
    let validated_limits = request.limits.validate()?;
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    {
        if let Some(filter) = request.filter.as_deref() {
            super::capture_filter::validate(&request.interface, filter)?;
        }
        let interface =
            super::interface_identity::validate_current_interface_identity(&request.interface)?;
        let netmask = capture_netmask(&interface);
        let parts = capture_backend::open_capture(
            &interface.id,
            validated_limits,
            request.filter.as_deref(),
            netmask,
            request.promiscuous,
        )?;
        Ok(Box::new(super::live_capture::NativeCaptureSession::spawn(
            parts,
            validated_limits,
        )?))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (request, validated_limits);
        Err(Error::Unsupported {
            message: "native Layer 2 capture is unsupported on this target".to_owned(),
        })
    }
}

#[cfg(not(feature = "native-layer2"))]
pub(crate) fn system_capture(
    _request: &capture::Request,
) -> Result<Box<dyn capture::Session>, Error> {
    Err(Error::Unsupported {
        message: "enable the native-layer2 feature for native packet capture".to_owned(),
    })
}

#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos", windows)
))]
fn capture_netmask(interface: &interface::Info) -> Option<u32> {
    let assigned = interface
        .addresses
        .iter()
        .find(|assigned| assigned.address.is_ipv4())?;
    let shift = u32::BITS.checked_sub(u32::from(assigned.prefix_length))?;
    Some(u32::MAX.checked_shl(shift).unwrap_or(0).to_be())
}

#[cfg(all(
    test,
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos", windows)
))]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use packetcraftr_core::frame::LinkType;

    use super::*;
    use crate::{interface::Id as InterfaceId, link::Capability};

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

        assert_eq!(capture_netmask(&interface), Some((u32::MAX << 24).to_be()));

        let mut ipv6_only = interface;
        ipv6_only.addresses = vec![interface::Address {
            address: IpAddr::V6(Ipv6Addr::LOCALHOST),
            prefix_length: 128,
        }];
        assert_eq!(capture_netmask(&ipv6_only), None);
    }
}
