// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Compile and behavior coverage for providers implemented outside the crate.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use bytes::Bytes;
use packetcraftr::{
    CaptureProvider, CaptureQueueLimits, CaptureSession, CaptureStatistics, CapturedFrame,
    DestinationScope, DispatchPacketIo, ExchangeIo, Hostname, HostnameResolver, InterfaceAddress,
    InterfaceFlags, InterfaceId, InterfaceInfo, InterfaceProvider, IoSendReport, Layer2Frame,
    Layer2Io, Layer3Frame, Layer3Io, LinkCapability, LinkMode, LinkType, LiveIoError, LiveTarget,
    MacAddress, MaterializedRoute, PacketIo, PlannedRoute, RouteDecision, RouteSelectionReason,
    TargetResolutionError, TrafficPolicy, TransmissionFrame,
};

#[derive(Clone, Copy)]
struct ExternalInterfaces;

impl InterfaceProvider for ExternalInterfaces {
    fn interfaces(&self) -> Result<Vec<InterfaceInfo>, LiveIoError> {
        Ok(vec![InterfaceInfo {
            id: InterfaceId {
                name: "external0".to_owned(),
                index: 9,
            },
            description: Some("external provider".to_owned()),
            mac_address: Some(MacAddress([0x02, 0, 0, 0, 0, 9])),
            addresses: vec![InterfaceAddress {
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
                prefix_length: 24,
            }],
            flags: InterfaceFlags {
                up: true,
                multicast: true,
                ..InterfaceFlags::default()
            },
            mtu: Some(1_500),
            capability: LinkCapability::Layer2And3,
            link_type: LinkType::ETHERNET,
        }])
    }
}

#[derive(Clone, Copy)]
struct ExternalLayer2;

impl Layer2Io for ExternalLayer2 {
    fn send_layer2(&self, frame: Layer2Frame<'_>) -> Result<IoSendReport, LiveIoError> {
        assert_eq!(frame.route().plan.mode, LinkMode::Layer2);
        Ok(IoSendReport {
            bytes_sent: frame.bytes().len(),
            wire_bytes: Some(frame.bytes().clone()),
        })
    }
}

#[derive(Clone, Copy)]
struct ExternalLayer3;

impl Layer3Io for ExternalLayer3 {
    fn send_layer3(&self, frame: Layer3Frame<'_>) -> Result<IoSendReport, LiveIoError> {
        assert_eq!(frame.route().plan.mode, LinkMode::Layer3);
        Ok(IoSendReport {
            bytes_sent: frame.bytes().len(),
            wire_bytes: None,
        })
    }
}

struct ExternalCapture;

struct ExternalHostnameResolver;

impl HostnameResolver for ExternalHostnameResolver {
    fn resolve(
        &self,
        _hostname: &Hostname,
        _limit: usize,
    ) -> Result<Vec<IpAddr>, TargetResolutionError> {
        Ok(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))])
    }
}

impl CaptureSession for ExternalCapture {
    fn wait_ready(&mut self) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<CapturedFrame>, LiveIoError> {
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn statistics(&self) -> CaptureStatistics {
        CaptureStatistics::default()
    }
}

struct ExternalExchange {
    packets: DispatchPacketIo<ExternalLayer2, ExternalLayer3>,
}

impl PacketIo for ExternalExchange {
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        self.packets.send(frame)
    }
}

impl CaptureProvider for ExternalExchange {
    type Capture = ExternalCapture;

    fn arm_capture(
        &self,
        _route: &PlannedRoute,
        limits: CaptureQueueLimits,
    ) -> Result<Self::Capture, LiveIoError> {
        limits.validate()?;
        Ok(ExternalCapture)
    }
}

fn route(mode: LinkMode) -> MaterializedRoute {
    MaterializedRoute {
        plan: PlannedRoute {
            route: RouteDecision {
                interface: InterfaceId {
                    name: "external0".to_owned(),
                    index: 9,
                },
                source_mac: Some(MacAddress([0x02, 0, 0, 0, 0, 9])),
                selected_address: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
                preferred_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
                next_hop: None,
                selection_reason: RouteSelectionReason::OnLink,
                destination_scope: DestinationScope::Private,
                mtu: 1_500,
                capability: LinkCapability::Layer2And3,
                link_type: LinkType::ETHERNET,
            },
            mode,
            lookup_destination: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            final_destination: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            visited_destinations: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))],
            packet_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
            neighbor_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
            neighbor_target: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            destination_mac: Some(MacAddress([0x02, 0, 0, 0, 0, 10])),
            source_mac: Some(MacAddress([0x02, 0, 0, 0, 0, 9])),
            neighbor_vlan_tags: Vec::new(),
            synthesized_ethernet: mode == LinkMode::Layer2,
        },
        neighbor_resolution: None,
    }
}

fn assert_exchange_provider<T: ExchangeIo>(_provider: &T) {}
fn assert_compatibility_paths<T>(_provider: &T)
where
    T: packetcraftr::client::PacketIo
        + packetcraftr::client::CaptureProvider
        + packetcraftr::client::ExchangeIo,
{
}

#[test]
fn external_provider_uses_only_platform_neutral_contracts() {
    let interfaces = ExternalInterfaces.interfaces().unwrap();
    assert_eq!(interfaces[0].id.name, "external0");

    let provider = ExternalExchange {
        packets: DispatchPacketIo::new(ExternalLayer2, ExternalLayer3),
    };
    assert_exchange_provider(&provider);
    assert_compatibility_paths(&provider);
    let _: packetcraftr::client::CaptureQueueLimits = CaptureQueueLimits::default();
    let _: packetcraftr::client::SystemLayer3Io = packetcraftr::SystemLayer3Io;
    let target = "lab.example".parse::<LiveTarget>().unwrap();
    let resolved = TrafficPolicy {
        allow_hostname_resolution: true,
        ..TrafficPolicy::default()
    }
    .resolve_target(&target, &ExternalHostnameResolver)
    .unwrap();
    assert_eq!(
        resolved.addresses(),
        &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]
    );

    let bytes = Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]);
    let layer2_route = route(LinkMode::Layer2);
    let layer3_route = route(LinkMode::Layer3);
    let unresolved_route = route(LinkMode::Auto);

    let layer2 = TransmissionFrame::try_new(&bytes, &layer2_route).unwrap();
    assert_eq!(provider.send(layer2).unwrap().bytes_sent, bytes.len());
    let layer3 = TransmissionFrame::try_new(&bytes, &layer3_route).unwrap();
    assert_eq!(provider.send(layer3).unwrap().bytes_sent, bytes.len());

    assert!(matches!(
        Layer2Frame::try_new(&bytes, &layer3_route),
        Err(LiveIoError::TransmissionModeMismatch {
            expected: LinkMode::Layer2,
            actual: LinkMode::Layer3,
        })
    ));
    assert!(matches!(
        Layer3Frame::try_new(&bytes, &layer2_route),
        Err(LiveIoError::TransmissionModeMismatch {
            expected: LinkMode::Layer3,
            actual: LinkMode::Layer2,
        })
    ));
    assert!(matches!(
        TransmissionFrame::try_new(&bytes, &unresolved_route),
        Err(LiveIoError::UnresolvedLinkMode)
    ));
}
