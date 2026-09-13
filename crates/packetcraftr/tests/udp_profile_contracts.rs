// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use bytes::Bytes;
use packetcraftr::{
    Client,
    clock::SystemClock,
    policy::{Policy, PolicyAuthorizer},
    probe::ExchangeExecutor,
    scan::{
        self,
        profile::{ByteCheck, Config, Payload, ResponseCheck, Status, UdpProfile},
    },
    target::Target,
};
use packetcraftr_core::{
    build::Builder,
    decode::Dissector,
    frame::{Frame, LinkType},
    layer::Raw,
    packet::Packet,
    protocol::{application::dns::Dns, builtin, network::Ipv4, transport::Udp},
};
use packetcraftr_netio::{
    self as net, capture,
    interface::Id,
    link::{Capability, Mode},
    neighbor, route, transmit,
};
use std::{
    collections::{BTreeMap, VecDeque},
    convert::Infallible,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};
fn dns_profile() -> Arc<UdpProfile> {
    Arc::new(
        UdpProfile::new(Config {
            name: "dns".to_owned(),
            request: Payload::Dns {
                name: "example.test.".to_owned(),
                query_type: 1,
                class: 1,
                recursion_desired: true,
                id_base: 10,
            },
            response: ResponseCheck::Dns,
        })
        .unwrap(),
    )
}
fn bytes_profile() -> Arc<UdpProfile> {
    Arc::new(
        UdpProfile::new(Config {
            name: "fixture service".to_owned(),
            request: Payload::Bytes {
                data: Bytes::from_static(b"probe"),
            },
            response: ResponseCheck::Bytes {
                checks: vec![ByteCheck {
                    offset: 1,
                    data: Bytes::from_static(&[0xa0]),
                    mask: Some(Bytes::from_static(&[0xf0])),
                }],
                min_length: 2,
                max_length: 8,
            },
        })
        .unwrap(),
    )
}
#[test]
fn explicit_checks_distinguish_dns_identity_bytes_and_unchecked_replies() {
    let profile = dns_profile();
    let query = profile.payload(7);
    let mut response = Dns::from_wire(query.clone()).unwrap();
    response.edit(|dns| dns.response = true);
    assert_eq!(
        profile
            .evaluate(&query, &response.to_wire().unwrap())
            .status,
        Status::Confirmed
    );
    response.edit(|dns| dns.id += 1);
    assert_eq!(
        profile
            .evaluate(&query, &response.to_wire().unwrap())
            .status,
        Status::Rejected
    );
    assert_ne!(profile.payload(7), profile.payload(8));
    let profile = bytes_profile();
    assert_eq!(
        profile.evaluate(b"probe", &[0, 0xab]).status,
        Status::Confirmed
    );
    assert_eq!(
        profile.evaluate(b"probe", &[0, 0x1b]).status,
        Status::Rejected
    );
    assert_eq!(profile.evaluate(b"probe", &[0]).status, Status::Rejected);
    let profile = UdpProfile::new(Config {
        name: "unvalidated".to_owned(),
        request: Payload::Bytes { data: Bytes::new() },
        response: ResponseCheck::Any,
    })
    .unwrap();
    assert_eq!(profile.evaluate(&[], b"anything").status, Status::Unchecked);
    let bad = Config {
        name: "bad".to_owned(),
        request: Payload::Bytes { data: Bytes::new() },
        response: ResponseCheck::Bytes {
            checks: vec![ByteCheck {
                offset: 65_535,
                data: Bytes::from_static(&[1]),
                mask: None,
            }],
            min_length: 0,
            max_length: 65_535,
        },
    };
    assert!(UdpProfile::new(bad).is_err());
}
#[derive(Default)]
struct State {
    queue: VecDeque<Frame>,
    sent: Vec<(u16, Bytes)>,
    arms: usize,
    stops: usize,
    wrong_only: bool,
}
#[derive(Clone)]
struct Io(Arc<Mutex<State>>);
struct Routes;
impl route::Provider for Routes {
    type Error = Infallible;
    fn lookup_with_preferences(
        &self,
        _: IpAddr,
        _: Option<&Id>,
        _: Option<IpAddr>,
    ) -> Result<route::Decision, Infallible> {
        Ok(route::Decision {
            interface: Id {
                index: 1,
                name: "fixture0".to_owned(),
            },
            source_mac: None,
            selected_source: Some("192.0.2.1".parse().unwrap()),
            preferred_source: None,
            next_hop: None,
            selection_reason: route::SelectionReason::OnLink,
            destination_scope: route::Scope::Link,
            mtu: 1500,
            capability: Capability::Layer3,
            link_type: LinkType::RAW,
        })
    }
}
struct NoNeighbors;
impl neighbor::Resolver for NoNeighbors {
    fn resolve(&self, _: &neighbor::Request) -> Result<neighbor::Resolution, neighbor::Error> {
        panic!("no layer-3 discovery")
    }
}
fn registry() -> Arc<packetcraftr_core::registry::Registry> {
    Arc::new(
        builtin::registry_with(|builder| {
            builder.bind("udp", 5353, "dns", 100)?;
            builder.bind("udp", 67, "raw", i32::MAX)?;
            Ok(())
        })
        .unwrap(),
    )
}
impl transmit::Sender for Io {
    fn send(&self, frame: transmit::Frame<'_>) -> Result<transmit::Report, net::Error> {
        let decoded = Dissector::new(registry())
            .decode(
                Frame::new(SystemTime::now(), LinkType::RAW, frame.bytes().clone()).unwrap(),
                Default::default(),
            )
            .unwrap();
        let ip = decoded.packet.get::<Ipv4>().unwrap();
        let udp = decoded.packet.get::<Udp>().unwrap();
        let mut state = self.0.lock().unwrap();
        state
            .sent
            .push((udp.destination_port, frame.bytes().slice(28..)));
        for correct in [false, true] {
            if correct && state.wrong_only {
                continue;
            }
            let mut response = Packet::new();
            response.push(Ipv4 {
                source: ip.destination,
                destination: ip.source,
                ..Default::default()
            });
            response.push(Udp {
                source_port: udp.destination_port,
                destination_port: udp.source_port,
                ..Default::default()
            });
            if udp.destination_port == 5353 {
                let mut dns = decoded.packet.get::<Dns>().unwrap().clone();
                dns.edit(|dns| {
                    dns.response = true;
                    if !correct {
                        dns.id = dns.id.wrapping_add(1);
                    }
                });
                response.push(dns);
            } else {
                response.push(Raw::new(if correct {
                    vec![0, 0xab]
                } else {
                    vec![0, 0x1b]
                }));
            }
            let built = Builder::new(registry())
                .build(response, Default::default(), Default::default())
                .unwrap();
            state
                .queue
                .push_back(Frame::new(SystemTime::now(), LinkType::RAW, built.bytes).unwrap());
        }
        Ok(transmit::Report::committed(
            frame.bytes().len(),
            frame.bytes().clone(),
        ))
    }
}
struct Capture {
    state: Arc<Mutex<State>>,
    metadata: capture::Metadata,
}
impl capture::Session for Capture {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }
    fn wait_ready(&mut self, _: Duration) -> Result<(), net::Error> {
        Ok(())
    }
    fn next_captured_frame(
        &mut self,
        _: Duration,
    ) -> Result<Option<capture::Captured>, net::Error> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .queue
            .pop_front()
            .map(|frame| capture::Captured::new(frame, Instant::now())))
    }
    fn shutdown(&mut self) -> Result<(), net::Error> {
        self.state.lock().unwrap().stops += 1;
        Ok(())
    }
    fn statistics(&self) -> capture::Statistics {
        capture::Statistics::default()
    }
}
impl capture::Provider for Io {
    type Capture = Capture;
    fn arm_capture(&self, request: &capture::Request) -> Result<Capture, net::Error> {
        self.0.lock().unwrap().arms += 1;
        Ok(Capture {
            state: self.0.clone(),
            metadata: capture::Metadata {
                interface: request.interface.clone(),
                link_type: LinkType::RAW,
                snap_length: request.limits.snap_length,
            },
        })
    }
}
fn run(window: usize, wrong_only: bool) -> (scan::Report, Arc<Mutex<State>>) {
    let profiles = BTreeMap::from([(5353, dns_profile()), (67, bytes_profile())]);
    let state = Arc::new(Mutex::new(State {
        wrong_only,
        ..Default::default()
    }));
    let policy = Policy {
        max_packets_per_operation: 8,
        max_bytes_per_operation: 8 * 1500,
        ..Default::default()
    };
    let registry = builtin::registry();
    let client = Client::new(
        registry.clone(),
        Routes,
        NoNeighbors,
        Io(state.clone()),
        policy.clone(),
    );
    let mut options = packetcraftr::exchange::Options::default();
    options.send.plan.link_mode = Mode::Layer3;
    options.capture.snap_length = 1500;
    let request = scan::Request {
        max_in_flight: window,
        targets: Target::Address("192.0.2.2".parse().unwrap()).into(),
        transport: scan::Transport::Udp,
        address_family: packetcraftr::target::Family::Any,
        ports: vec![5353, 67],
        attempts: 1,
        timeout: Duration::from_millis(200),
        probes_per_second: None,
        udp_payload: Bytes::from_static(b"fallback"),
        udp_profiles: profiles,
        limits: scan::Limits {
            max_duration: Duration::from_secs(3),
            ..Default::default()
        },
    };
    let report = scan::run(
        &request,
        &mut PolicyAuthorizer::for_packets(&policy),
        &registry,
        &mut ExchangeExecutor::new(&client, options),
        &mut SystemClock,
    )
    .unwrap();
    (report, state)
}
#[test]
fn serial_and_rolling_scans_prefer_valid_application_replies_and_bind_custom_ports() {
    for window in [1, 2] {
        let (report, state) = run(window, false);
        assert_eq!(report.endpoints.len(), 2);
        for endpoint in report.endpoints {
            assert_eq!(endpoint.classification, scan::Classification::Open);
            assert_eq!(
                endpoint.probes[0].application.as_ref().unwrap().status,
                Status::Confirmed
            );
        }
        let state = state.lock().unwrap();
        assert_eq!(state.sent[1].1.as_ref(), b"probe");
        assert_eq!(state.arms, if window == 1 { 2 } else { 1 });
        assert_eq!(state.arms, state.stops);
    }
}
#[test]
fn reverse_flow_reachability_does_not_imply_application_confirmation() {
    let (report, _) = run(2, true);
    for endpoint in report.endpoints {
        assert_eq!(endpoint.classification, scan::Classification::Open);
        assert_eq!(
            endpoint.probes[0].application.as_ref().unwrap().status,
            Status::Rejected
        );
    }
}
