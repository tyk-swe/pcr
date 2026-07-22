// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Compile and behavior coverage for providers implemented outside the crate.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use packetcraftr::{
    capture::{Frame as CapturedFrame, LinkType},
    client::{
        policy::Policy,
        target::{Error as TargetResolutionError, Hostname, Resolver, Target},
    },
    net::{
        Error,
        capture::{
            Captured as CapturedCaptureFrame, Limits as CaptureLimits, Provider as CaptureProvider,
            Session as CaptureSession, Statistics as CaptureStatistics,
        },
        exchange::Io as ExchangeIo,
        interface::{Address, Flags, Id, Info, Provider as InterfaceProvider},
        link::{Capability, MacAddress, Mode},
        route::{Decision, Materialized, Plan, Scope, SelectionReason},
        transmit::{
            Dispatch, Frame as TransmissionFrame, Layer2Frame, Layer2Sender, Layer3Frame,
            Layer3Sender, Report, Sender,
        },
    },
};

#[derive(Clone, Copy)]
struct ExternalInterfaces;

impl InterfaceProvider for ExternalInterfaces {
    fn interfaces(&self) -> Result<Vec<Info>, Error> {
        Ok(vec![Info {
            id: Id {
                name: "external0".to_owned(),
                index: 9,
            },
            description: Some("external provider".to_owned()),
            mac_address: Some(MacAddress([0x02, 0, 0, 0, 0, 9])),
            addresses: vec![Address {
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
                prefix_length: 24,
            }],
            flags: Flags {
                up: true,
                multicast: true,
                ..Flags::default()
            },
            mtu: Some(1_500),
            capability: Capability::Layer2And3,
            link_type: LinkType::ETHERNET,
        }])
    }
}

#[derive(Clone, Copy)]
struct ExternalLayer2;

impl Layer2Sender for ExternalLayer2 {
    fn send_layer2(&self, frame: Layer2Frame<'_>) -> Result<Report, Error> {
        assert_eq!(frame.route().plan.mode, Mode::Layer2);
        Ok(Report {
            bytes_sent: frame.bytes().len(),
            wire_bytes: Some(frame.bytes().clone()),
        })
    }
}

#[derive(Clone, Copy)]
struct ExternalLayer3;

impl Layer3Sender for ExternalLayer3 {
    fn send_layer3(&self, frame: Layer3Frame<'_>) -> Result<Report, Error> {
        assert_eq!(frame.route().plan.mode, Mode::Layer3);
        Ok(Report {
            bytes_sent: frame.bytes().len(),
            wire_bytes: None,
        })
    }
}

struct ExternalCapture {
    limits: CaptureLimits,
    ready: bool,
    frame: Option<CapturedFrame>,
    shutdowns: usize,
    statistics: CaptureStatistics,
}

struct ExternalHostnameResolver;

impl Resolver for ExternalHostnameResolver {
    fn resolve(
        &self,
        _hostname: &Hostname,
        _limit: usize,
    ) -> Result<Vec<IpAddr>, TargetResolutionError> {
        Ok(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))])
    }
}

impl CaptureSession for ExternalCapture {
    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), Error> {
        self.ready = true;
        Ok(())
    }

    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<CapturedFrame>, Error> {
        assert!(
            self.ready,
            "capture must be explicitly readied before polling"
        );
        Ok(self.frame.take())
    }

    fn shutdown(&mut self) -> Result<(), Error> {
        self.shutdowns += 1;
        Ok(())
    }

    fn statistics(&self) -> CaptureStatistics {
        self.statistics
    }
}

struct ExternalExchange {
    packets: Dispatch<ExternalLayer2, ExternalLayer3>,
}

impl Sender for ExternalExchange {
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<Report, Error> {
        self.packets.send(frame)
    }
}

impl CaptureProvider for ExternalExchange {
    type Capture = ExternalCapture;

    fn arm_capture(&self, _route: &Plan, limits: CaptureLimits) -> Result<Self::Capture, Error> {
        limits.validate()?;
        Ok(ExternalCapture {
            limits,
            ready: false,
            frame: Some(
                CapturedFrame::new(
                    SystemTime::UNIX_EPOCH,
                    LinkType::ETHERNET,
                    Bytes::from_static(&[0xca, 0xfe]),
                )
                .unwrap(),
            ),
            shutdowns: 0,
            statistics: CaptureStatistics {
                received_frames: 1,
                received_bytes: 2,
                ..CaptureStatistics::default()
            },
        })
    }
}

fn route(mode: Mode) -> Materialized {
    Materialized {
        plan: Plan {
            route: Decision {
                interface: Id {
                    name: "external0".to_owned(),
                    index: 9,
                },
                source_mac: Some(MacAddress([0x02, 0, 0, 0, 0, 9])),
                selected_address: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
                preferred_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
                next_hop: None,
                selection_reason: SelectionReason::OnLink,
                destination_scope: Scope::Private,
                mtu: 1_500,
                capability: Capability::Layer2And3,
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
            synthesized_ethernet: mode == Mode::Layer2,
        },
        neighbor_resolution: None,
    }
}

fn assert_exchange_provider<T: ExchangeIo>(_provider: &T) {}

#[test]
fn external_provider_uses_only_platform_neutral_contracts() {
    let interfaces = ExternalInterfaces.interfaces().unwrap();
    assert_eq!(interfaces[0].id.name, "external0");

    let provider = ExternalExchange {
        packets: Dispatch::new(ExternalLayer2, ExternalLayer3),
    };
    assert_exchange_provider(&provider);
    let target = "lab.example".parse::<Target>().unwrap();
    let resolved = Policy {
        allow_hostname_resolution: true,
        ..Policy::default()
    }
    .resolve_target(&target, &ExternalHostnameResolver)
    .unwrap();
    assert_eq!(
        resolved.addresses(),
        &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]
    );

    let bytes = Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]);
    let layer2_route = route(Mode::Layer2);
    let layer3_route = route(Mode::Layer3);
    let unresolved_route = route(Mode::Auto);

    let layer2 = TransmissionFrame::try_new(&bytes, &layer2_route).unwrap();
    assert_eq!(provider.send(layer2).unwrap().bytes_sent, bytes.len());
    let layer3 = TransmissionFrame::try_new(&bytes, &layer3_route).unwrap();
    assert_eq!(provider.send(layer3).unwrap().bytes_sent, bytes.len());

    assert!(matches!(
        Layer2Frame::try_new(&bytes, &layer3_route),
        Err(Error::TransmissionModeMismatch {
            expected: Mode::Layer2,
            actual: Mode::Layer3,
        })
    ));
    assert!(matches!(
        Layer3Frame::try_new(&bytes, &layer2_route),
        Err(Error::TransmissionModeMismatch {
            expected: Mode::Layer3,
            actual: Mode::Layer2,
        })
    ));
    assert!(matches!(
        TransmissionFrame::try_new(&bytes, &unresolved_route),
        Err(Error::UnresolvedLinkMode)
    ));
}

#[test]
fn external_capture_provider_lifecycle_is_platform_neutral() {
    let provider = ExternalExchange {
        packets: Dispatch::new(ExternalLayer2, ExternalLayer3),
    };
    let route = route(Mode::Layer2);
    let limits = CaptureLimits {
        max_frames: 8,
        max_bytes: 256,
        snap_length: 128,
        ..CaptureLimits::default()
    };

    let mut capture = provider.arm_capture(&route.plan, limits).unwrap();
    assert_eq!(capture.limits, limits);
    assert!(!capture.ready);
    assert_eq!(capture.shutdowns, 0);

    capture.wait_ready(Duration::from_millis(1)).unwrap();
    assert!(capture.ready);
    let captured = capture
        .next_captured_frame(Duration::ZERO)
        .unwrap()
        .unwrap();
    let CapturedCaptureFrame { frame, received_at } = captured;
    assert!(received_at.is_none());
    assert_eq!(frame.bytes().as_ref(), &[0xca, 0xfe]);
    assert!(
        capture
            .next_captured_frame(Duration::ZERO)
            .unwrap()
            .is_none()
    );
    assert_eq!(capture.statistics().validate().unwrap().received_frames, 1);

    capture.shutdown().unwrap();
    assert_eq!(capture.shutdowns, 1);

    let invalid = provider.arm_capture(
        &route.plan,
        CaptureLimits {
            max_frames: 0,
            ..limits
        },
    );
    assert!(matches!(
        invalid,
        Err(Error::InvalidCaptureQueueLimit { .. })
    ));
}

#[test]
fn external_capture_statistics_contract_reports_invalid_loss_counters() {
    let invalid = CaptureStatistics {
        dropped_bytes: 1,
        ..CaptureStatistics::default()
    };
    assert!(matches!(
        invalid.validate(),
        Err(Error::InvalidCaptureStatistics { .. })
    ));
}
