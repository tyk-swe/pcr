// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::capture_file::{Reader, Writer};
use packetcraftr_core::error::{Classification, Classified, Kind};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::packet::MacAddress;
use packetcraftr_netio::{
    Error as LiveIoError,
    interface::Id as InterfaceId,
    link::{Capability as LinkCapability, Mode as LinkMode},
    route::{Decision, Scope, SelectionReason},
    transmit::{Report as IoSendReport, Submission},
};

use super::admission::ReplayAdmission;
use super::engine::run;
use super::error::Error;
use super::evidence::FrameEvidence;
use super::executor::Executor;
use super::report::Report;
use super::request::{Limits, Options, Parts, Request, Selector, Source, Timing};
use crate::clock::Clock;
use crate::policy::WireLimits;
use crate::route::{Interface, Materialized as MaterializedRoute, Plan as RoutePlan};
use crate::test_support::RecordingClock;
use packetcraftr_core::error::BoundaryError;

#[derive(Default)]
struct RecordingAuthorizer {
    calls: usize,
    final_wire_calls: usize,
    limits: Vec<(u64, u64)>,
    deny: bool,
    deny_final_wire: bool,
}

impl ReplayAdmission for RecordingAuthorizer {
    fn admit_frame(
        &mut self,
        limits: WireLimits,
        _frame: &Frame,
        _mode: LinkMode,
    ) -> Result<(), BoundaryError> {
        self.calls += 1;
        self.limits.push((limits.packets(), limits.wire_bytes()));
        if self.deny {
            Err(BoundaryError::new(
                "denied by test policy",
                Classification::new("policy.test", Kind::Policy, None),
                Vec::new(),
            ))
        } else {
            Ok(())
        }
    }

    fn authorize_final_wire(
        &mut self,
        _frame: &Frame,
        _route: &RoutePlan,
    ) -> Result<(), BoundaryError> {
        self.final_wire_calls += 1;
        if self.deny_final_wire {
            Err(BoundaryError::new(
                "final wire route denied by test policy",
                Classification::new("policy.source_ownership", Kind::Policy, None),
                Vec::new(),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct RecordingTransmitter {
    validation_calls: usize,
    transmission_calls: usize,
    partial: bool,
    resolves_to: Option<InterfaceId>,
}

impl Executor for RecordingTransmitter {
    fn plan_frame(
        &mut self,
        interface: &Interface,
        mode: LinkMode,
        frame: &Frame,
        _deadline: &Deadline,
    ) -> Result<MaterializedRoute, LiveIoError> {
        self.validation_calls += 1;
        let interface = match (&self.resolves_to, interface) {
            (Some(resolved), _) | (None, Interface::Id(resolved)) => resolved,
            (None, unresolved) => panic!("{unresolved:?} needs a resolved identity"),
        };
        Ok(MaterializedRoute {
            plan: test_route(interface, mode, frame.link_type),
            neighbor_resolution: None,
        })
    }

    fn transmit(
        &mut self,
        _route: &MaterializedRoute,
        frame: &Frame,
    ) -> Result<IoSendReport, LiveIoError> {
        self.transmission_calls += 1;
        Ok(Submission::start().complete(
            if self.partial {
                frame.bytes().len().saturating_sub(1)
            } else {
                frame.bytes().len()
            },
            frame.bytes().clone(),
        ))
    }
}

struct AllFrames;

impl Selector for AllFrames {
    fn select(&mut self, _source_index: u64, _frame: &Frame) -> Result<bool, Error> {
        Ok(true)
    }

    fn interface(&mut self, _source_index: u64, _frame: &Frame) -> Result<Interface, Error> {
        Ok(Interface::Id(test_interface()))
    }
}

struct Through(Interface);

impl Selector for Through {
    fn select(&mut self, _source_index: u64, _frame: &Frame) -> Result<bool, Error> {
        Ok(true)
    }

    fn interface(&mut self, _source_index: u64, _frame: &Frame) -> Result<Interface, Error> {
        Ok(self.0.clone())
    }
}

struct RecordingSelector {
    numbers: Vec<u64>,
    skip: Option<u64>,
    keep: bool,
}

impl Selector for RecordingSelector {
    fn select(&mut self, source_index: u64, _frame: &Frame) -> Result<bool, Error> {
        let number = source_index + 1;
        self.numbers.push(number);
        Ok(self.keep && self.skip != Some(number))
    }

    fn interface(&mut self, _source_index: u64, _frame: &Frame) -> Result<Interface, Error> {
        Ok(Interface::Id(test_interface()))
    }
}

fn test_interface() -> InterfaceId {
    InterfaceId {
        name: "test0".to_owned(),
        index: 7,
    }
}

fn test_route(interface: &InterfaceId, mode: LinkMode, link_type: LinkType) -> RoutePlan {
    let selected_source = "192.0.2.1".parse().expect("fixture source");
    let source_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
    RoutePlan {
        decision: Decision {
            interface: interface.clone(),
            source_mac: Some(source_mac),
            selected_source: Some(selected_source),
            preferred_source: None,
            next_hop: None,
            selection_reason: SelectionReason::InterfaceOnly,
            destination_scope: Scope::Link,
            mtu: 1_500,
            capability: LinkCapability::Layer2AndLayer3,
            link_type,
        },
        mode,
        lookup_destination: None,
        final_destination: None,
        visited_destinations: Vec::new(),
        packet_source: Some(selected_source),
        neighbor_source: None,
        neighbor_target: None,
        destination_mac: None,
        source_mac: Some(source_mac),
        neighbor_vlan_tags: Vec::new(),
        synthesized_ethernet: false,
    }
}

fn capture_reader(link_type: LinkType, frames: &[(Duration, &[u8])]) -> Reader<Cursor<Vec<u8>>> {
    let mut writer = Writer::pcap(Vec::new(), link_type).expect("pcap writer");
    for (offset, bytes) in frames {
        writer
            .write_frame(
                &Frame::new(UNIX_EPOCH + *offset, link_type, bytes.to_vec())
                    .expect("capture frame"),
            )
            .expect("write capture frame");
    }
    Reader::new(Cursor::new(writer.into_inner())).expect("capture reader")
}

fn replay_options(timing: Timing) -> Options {
    Options {
        repeat: 1,
        inter_pass_delay: Duration::ZERO,
        link_mode: LinkMode::Auto,
        timing,
        max_gap: None,
        limits: Limits::default(),
        allow_permissive_live: false,
    }
}

fn replay_source<R: std::io::Read, S: Selector, C: Clock>(
    source: Source<R>,
    options: &Options,
    selector: S,
    authorizer: &mut RecordingAuthorizer,
    transmitter: &mut RecordingTransmitter,
    clock: &mut C,
    emit: impl FnMut(FrameEvidence, &Deadline) -> Result<(), Error>,
) -> Result<Report, Error> {
    run(
        Parts {
            source,
            selector,
            options: options.clone(),
        },
        authorizer,
        transmitter,
        clock,
        Deadline::new(options.limits.max_duration),
        emit,
    )
}

fn replay_seekable<S: Selector, C: Clock>(
    reader: Reader<Cursor<Vec<u8>>>,
    options: &Options,
    selector: S,
    authorizer: &mut RecordingAuthorizer,
    transmitter: &mut RecordingTransmitter,
    clock: &mut C,
    emit: impl FnMut(FrameEvidence, &Deadline) -> Result<(), Error>,
) -> Result<Report, Error> {
    replay_source(
        Source::seekable(reader),
        options,
        selector,
        authorizer,
        transmitter,
        clock,
        emit,
    )
}

fn replay<S: Selector, C: Clock>(
    reader: Reader<Cursor<Vec<u8>>>,
    options: &Options,
    selector: S,
    authorizer: &mut RecordingAuthorizer,
    transmitter: &mut RecordingTransmitter,
    clock: &mut C,
    emit: impl FnMut(FrameEvidence, &Deadline) -> Result<(), Error>,
) -> Result<Report, Error> {
    replay_source(
        Source::stream(reader),
        options,
        selector,
        authorizer,
        transmitter,
        clock,
        emit,
    )
}

#[test]
fn replay_refuses_unschedulable_fixed_rate() {
    let frames = [(Duration::ZERO, &[1_u8][..]), (Duration::ZERO, &[2_u8][..])];
    for rate in [1e10, 1e300, f64::MIN_POSITIVE, 1e-300] {
        let mut authorizer = RecordingAuthorizer::default();
        let mut transmitter = RecordingTransmitter::default();
        let error = replay(
            capture_reader(LinkType::ETHERNET, &frames),
            &replay_options(Timing::FixedRate(rate)),
            AllFrames,
            &mut authorizer,
            &mut transmitter,
            &mut RecordingClock::default(),
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                Error::InvalidTiming { mode: "fixed_rate", value } if value == rate
            ),
            "{rate}: {error:?}"
        );
        assert_eq!(authorizer.calls, 0, "{rate}");
        assert_eq!(transmitter.transmission_calls, 0, "{rate}");
    }
}

#[test]
fn replay_authorization_denial_has_no_later_io_side_effects() {
    let reader = capture_reader(LinkType::ETHERNET, &[(Duration::ZERO, &[1])]);
    let mut authorizer = RecordingAuthorizer {
        deny: true,
        ..RecordingAuthorizer::default()
    };
    let mut transmitter = RecordingTransmitter::default();
    let mut clock = RecordingClock::default();
    let error = replay(
        reader,
        &replay_options(Timing::Immediate),
        AllFrames,
        &mut authorizer,
        &mut transmitter,
        &mut clock,
        |_, _| Ok(()),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        Error::Authorization {
            source_index: 0,
            ..
        }
    ));
    assert_eq!(authorizer.calls, 1);
    assert_eq!(authorizer.final_wire_calls, 0);
    assert_eq!(transmitter.validation_calls, 0);
    assert_eq!(transmitter.transmission_calls, 0);
    assert!(clock.delays().is_empty());
}

struct StartupCost {
    clock: RecordingClock,
    cost: Duration,
}

impl Selector for StartupCost {
    fn select(&mut self, _source_index: u64, _frame: &Frame) -> Result<bool, Error> {
        Ok(true)
    }

    fn interface(&mut self, source_index: u64, _frame: &Frame) -> Result<Interface, Error> {
        if source_index == 0 {
            self.clock.advance(self.cost);
        }
        Ok(Interface::Id(test_interface()))
    }
}

fn replay_after_setup(
    max_duration: Duration,
) -> (
    Result<Report, Error>,
    RecordingAuthorizer,
    RecordingTransmitter,
) {
    let millis = Duration::from_millis;
    let clock = RecordingClock::default();
    let mut options = replay_options(Timing::Original);
    options.limits.max_duration = max_duration;
    let mut authorizer = RecordingAuthorizer::default();
    let mut transmitter = RecordingTransmitter::default();
    let result = run(
        Parts {
            source: Source::stream(capture_reader(
                LinkType::ETHERNET,
                &[
                    (Duration::ZERO, &[1]),
                    (millis(1), &[2]),
                    (millis(2), &[3]),
                    (millis(3), &[4]),
                ],
            )),
            selector: StartupCost {
                clock: clock.clone(),
                cost: millis(5),
            },
            options,
        },
        &mut authorizer,
        &mut transmitter,
        &mut clock.clone(),
        clock.deadline(max_duration),
        |_, _| Ok(()),
    );
    (result, authorizer, transmitter)
}

struct MappedInterfaces;
impl Selector for MappedInterfaces {
    fn select(&mut self, _: u64, _: &Frame) -> Result<bool, Error> {
        Ok(true)
    }
    fn interface(&mut self, source_index: u64, _: &Frame) -> Result<Interface, Error> {
        let number = source_index + 1;
        Ok(Interface::Id(InterfaceId {
            name: format!("test{number}"),
            index: 6 + u32::try_from(number).expect("fixture index"),
        }))
    }
}

mod client {
    use std::sync::{Arc, Mutex};

    use packetcraftr_core::build::Builder;
    use packetcraftr_core::packet::Packet;
    use packetcraftr_core::protocol::{
        link::Ethernet,
        network::{Icmpv4, Ipv4},
    };
    use packetcraftr_netio::interface::{self, Address, Flags};

    use super::*;
    use crate::policy::Policy;
    use packetcraftr_core::filter::{Filter, FrameSelector, Limits as FilterLimits};

    use crate::replay::{
        Collector,
        routing::{Condition, Routing, Rule},
    };
    use crate::test_support::{Call, FakeProviders};
    use crate::{Client, ProviderSet};

    const INTERFACE_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);

    type Providers = ProviderSet<
        FakeProviders,
        Interfaces,
        FakeProviders,
        FakeProviders,
        FakeProviders,
        FakeProviders,
    >;

    #[derive(Clone)]
    struct Interfaces(Arc<Mutex<Vec<Call>>>);

    impl interface::Provider for Interfaces {
        fn interfaces(
            &self,
            _deadline: &Deadline,
        ) -> Result<Vec<interface::Info>, interface::Error> {
            self.0
                .lock()
                .expect("fake provider calls")
                .push(Call::Interfaces);
            let info = |id| interface::Info {
                id,
                description: None,
                mac_address: Some(INTERFACE_MAC),
                addresses: vec![Address {
                    address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                    prefix_length: 24,
                }],
                flags: Flags {
                    up: true,
                    ..Flags::default()
                },
                mtu: Some(1_500),
                capability: LinkCapability::Layer2AndLayer3,
                link_type: LinkType::ETHERNET,
            };
            Ok(vec![info(test_interface()), info(second_interface())])
        }
    }

    fn second_interface() -> InterfaceId {
        InterfaceId {
            name: "test1".to_owned(),
            index: 8,
        }
    }

    fn client(policy: Policy) -> (Client<Providers>, FakeProviders) {
        let fake = FakeProviders::default();
        let providers = ProviderSet {
            route: fake.clone(),
            interface: Interfaces(Arc::clone(&fake.calls)),
            capture: fake.clone(),
            transmit: fake.clone(),
            tcp: fake.clone(),
            resolver: fake.clone(),
        };
        let client = Client::new(
            packetcraftr_core::protocol::builtin::registry(),
            policy,
            providers,
        );
        (client, fake)
    }

    fn permissive() -> Policy {
        Policy {
            allow_permissive_packets: true,
            ..Policy::default()
        }
    }

    fn owned_frame(ttl: u8) -> Vec<u8> {
        let mut packet = Packet::new();
        packet
            .push(Ethernet {
                source: INTERFACE_MAC.0,
                destination: [0x02, 0, 0, 0, 0, 2],
                ..Ethernet::default()
            })
            .push(Ipv4 {
                source: Ipv4Addr::new(192, 0, 2, 1),
                destination: Ipv4Addr::new(192, 0, 2, 2),
                ttl,
                ..Ipv4::default()
            })
            .push(Icmpv4::default());
        Builder::new(packetcraftr_core::protocol::builtin::registry())
            .build(
                packet,
                packetcraftr_core::codec::Context::default(),
                packetcraftr_core::build::Options::default(),
            )
            .expect("replay fixture builds")
            .bytes
            .to_vec()
    }

    fn request(frames: &[Vec<u8>]) -> Request<Cursor<Vec<u8>>> {
        routed_request(frames, Routing::from(Interface::Id(test_interface())))
    }

    fn routed_request(frames: &[Vec<u8>], routing: Routing) -> Request<Cursor<Vec<u8>>> {
        let frames = frames
            .iter()
            .map(|bytes| (Duration::ZERO, bytes.as_slice()))
            .collect::<Vec<_>>();
        let mut options = replay_options(Timing::Immediate);
        options.allow_permissive_live = true;
        Request::new(
            Source::stream(capture_reader(LinkType::ETHERNET, &frames)),
            routing,
            options,
        )
    }

    fn filter_routing(rules: &[(&str, Interface)]) -> Routing {
        let registry = packetcraftr_core::protocol::builtin::registry();
        let rules = rules
            .iter()
            .map(|(filter, interface)| Rule {
                condition: Condition::Filter(
                    FrameSelector::new(
                        Arc::clone(&registry),
                        Filter::compile(filter, &registry, FilterLimits::default())
                            .expect("fixture filter compiles"),
                        1_500,
                    )
                    .expect("frame filter"),
                ),
                interface: interface.clone(),
            })
            .collect();
        Routing::new(rules, None).expect("bounded rules")
    }

    #[test]
    fn a_frame_the_policy_denies_consults_no_provider() {
        let (client, fake) = client(Policy::default());

        let error = client
            .replay(request(&[owned_frame(64)]), Collector::default())
            .expect_err("the default policy refuses permissive rebuilds");

        assert_eq!(error.classification().code, "policy.permissive_packet");
        assert!(fake.calls().is_empty(), "{:?}", fake.calls());
    }
}
