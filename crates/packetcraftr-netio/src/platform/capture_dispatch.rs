// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native capture capability dispatch.

#![forbid(unsafe_code)]

use crate::{
    Error as LiveIoError,
    capture::{CaptureQueueLimits, CaptureSession},
    route::Plan,
};

#[cfg(all(feature = "native-layer2", windows))]
use super::npcap as capture_backend;
#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos")
))]
use super::pcap_backend as capture_backend;

#[cfg(feature = "native-layer2")]
pub(crate) fn system_capture(
    route: &Plan,
    limits: CaptureQueueLimits,
    capture_filter: Option<&str>,
) -> Result<Box<dyn CaptureSession>, LiveIoError> {
    let validated_limits = limits.validate()?;
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    {
        if let Some(filter) = capture_filter {
            super::capture_filter::validate(&route.decision.interface, filter)?;
        }
        let interface = super::interface_identity::validate_current_interface_identity(
            &route.decision.interface,
        )?;
        let netmask = capture_netmask(route.decision.selected_source, &interface);
        let parts = capture_backend::open_capture(
            &route.decision.interface,
            validated_limits,
            capture_filter,
            netmask,
        )?;
        Ok(Box::new(super::live_capture::NativeCaptureSession::spawn(
            parts,
            validated_limits,
        )?))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (route, validated_limits, capture_filter);
        Err(LiveIoError::Unsupported {
            message: "native Layer 2 capture is unsupported on this target".to_owned(),
        })
    }
}

#[cfg(not(feature = "native-layer2"))]
pub(crate) fn system_capture(
    _route: &Plan,
    _limits: CaptureQueueLimits,
    _capture_filter: Option<&str>,
) -> Result<Box<dyn CaptureSession>, LiveIoError> {
    Err(LiveIoError::Unsupported {
        message: "enable the native-layer2 feature for native packet capture".to_owned(),
    })
}

#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos", windows)
))]
fn capture_netmask(
    selected_source: Option<std::net::IpAddr>,
    interface: &crate::interface::InterfaceInfo,
) -> Option<u32> {
    let selected_source = match selected_source {
        Some(std::net::IpAddr::V4(address)) => Some(address),
        _ => None,
    };
    let assigned = selected_source
        .and_then(|selected| {
            interface
                .addresses
                .iter()
                .find(|assigned| assigned.address == std::net::IpAddr::V4(selected))
        })
        .or_else(|| {
            interface
                .addresses
                .iter()
                .find(|assigned| assigned.address.is_ipv4())
        })?;
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
    use crate::{
        interface::{
            Address as InterfaceAddress, Flags as InterfaceFlags, Id as InterfaceId,
            Info as InterfaceInfo,
        },
        link::Capability,
    };

    #[test]
    fn capture_netmask_prefers_the_selected_ipv4_assignment() {
        let interface = InterfaceInfo {
            id: InterfaceId {
                name: "fixture0".to_owned(),
                index: 7,
            },
            description: None,
            mac_address: None,
            addresses: vec![
                InterfaceAddress {
                    address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    prefix_length: 8,
                },
                InterfaceAddress {
                    address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                    prefix_length: 24,
                },
            ],
            flags: InterfaceFlags::default(),
            mtu: None,
            capability: Capability::Layer2AndLayer3,
            link_type: LinkType::ETHERNET,
        };

        assert_eq!(
            capture_netmask(Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))), &interface),
            Some((u32::MAX << 8).to_be())
        );
        assert_eq!(
            capture_netmask(Some(IpAddr::V6(Ipv6Addr::LOCALHOST)), &interface),
            Some((u32::MAX << 24).to_be())
        );

        let mut ipv6_only = interface;
        ipv6_only.addresses = vec![InterfaceAddress {
            address: IpAddr::V6(Ipv6Addr::LOCALHOST),
            prefix_length: 128,
        }];
        assert_eq!(capture_netmask(None, &ipv6_only), None);
    }
}
