// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
#[test]
fn permissive_send_requires_option_and_policy_approval() {
    let registry = Arc::new(default_registry().unwrap());
    let client = Client::new(
        registry,
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        RejectingPacketIo,
        TrafficPolicy {
            allow_permissive_packets: true,
            ..TrafficPolicy::default()
        },
    );
    let mut request = packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        12345,
        9,
    );
    request.get_mut::<Ipv4>().unwrap().total_length = WireValue::Exact(1);
    let error = client
        .send(
            request,
            SendOptions {
                build: BuildOptions {
                    mode: crate::packet::build::BuildMode::Permissive,
                    ..BuildOptions::default()
                },
                plan: PlanOptions {
                    link_mode: LinkMode::Layer3,
                    interface: None,
                    preferred_source: None,
                },
                ..SendOptions::default()
            },
        )
        .unwrap_err();
    assert!(matches!(error, ClientError::PermissiveLiveOptInRequired));
}

#[test]
fn send_materializes_route_selected_ip_source() {
    let io = RecordingIo::default();
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        io.clone(),
        TrafficPolicy::default(),
    );
    let request = packet(Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(10, 0, 0, 2), 12345, 9);

    let report = client
        .send(
            request,
            SendOptions {
                plan: PlanOptions {
                    link_mode: LinkMode::Layer3,
                    interface: None,
                    preferred_source: None,
                },
                ..SendOptions::default()
            },
        )
        .unwrap();

    assert_eq!(&report.built.bytes[12..16], &[10, 0, 0, 1]);
    assert_eq!(io.0.lock().unwrap()[0], report.built.bytes);
}

#[test]
fn send_materializes_only_the_outer_ip_envelope() {
    let io = RecordingIo::default();
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        io,
        TrafficPolicy::default(),
    );
    let mut request = Packet::new();
    request
        .push(Ipv4::default())
        .push(Ipv4::default())
        .push(Udp::default());

    let report = client
        .send(
            request,
            SendOptions {
                destination: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
                plan: PlanOptions {
                    link_mode: LinkMode::Layer3,
                    interface: None,
                    preferred_source: None,
                },
                ..SendOptions::default()
            },
        )
        .unwrap();
    let envelopes = report
        .built
        .packet
        .iter()
        .filter_map(|layer| layer.as_any().downcast_ref::<Ipv4>())
        .collect::<Vec<_>>();

    assert_eq!(envelopes.len(), 2);
    assert_eq!(envelopes[0].source, Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(envelopes[0].destination, Ipv4Addr::new(10, 0, 0, 2));
    assert!(envelopes[1].source.is_unspecified());
    assert!(envelopes[1].destination.is_unspecified());
}

#[test]
fn send_materializes_resolved_and_interface_owned_macs() {
    let io = RecordingIo::default();
    let neighbors = CountingNeighbors::default();
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(RouteDecision {
            capability: LinkCapability::Layer2And3,
            link_type: LinkType::ETHERNET,
            ..route(LinkCapability::Layer2And3)
        }),
        neighbors.clone(),
        io,
        TrafficPolicy::default(),
    );
    let mut request = packet(Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(10, 0, 0, 2), 12345, 9);
    request.insert(0, Ethernet::default()).unwrap();

    let report = client
        .send(
            request,
            SendOptions {
                plan: PlanOptions {
                    link_mode: LinkMode::Layer2,
                    interface: None,
                    preferred_source: None,
                },
                ..SendOptions::default()
            },
        )
        .unwrap();

    assert_eq!(&report.built.bytes[..6], &[0, 1, 2, 3, 4, 5]);
    assert_eq!(&report.built.bytes[6..12], &[2, 0, 0, 0, 0, 1]);
    assert_eq!(neighbors.0.load(Ordering::SeqCst), 1);
}

#[test]
fn built_in_ethernet_mac_patch_matches_a_full_rebuild_and_keeps_metadata() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let mut packet = packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        12_345,
        9,
    );
    packet.insert(0, Ethernet::default()).unwrap();
    let mut patched = builder
        .build(
            packet.clone(),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    let mut materialized = packet;
    let ethernet = materialized.get_mut::<Ethernet>().unwrap();
    ethernet.destination = [0, 1, 2, 3, 4, 5];
    ethernet.source = [2, 0, 0, 0, 0, 1];

    assert!(patch_builtin_ethernet(
        &registry,
        &mut patched,
        &materialized
    ));
    let rebuilt = builder
        .build(
            materialized,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();

    assert_eq!(patched.bytes, rebuilt.bytes);
    assert!(patched.packet.structurally_eq(&rebuilt.packet));
    assert_eq!(patched.layout, rebuilt.layout);
    assert_eq!(patched.diagnostics, rebuilt.diagnostics);
    assert_eq!(
        (0..patched.packet.len())
            .map(|index| patched.packet.encoded_payload_length(index))
            .collect::<Vec<_>>(),
        (0..rebuilt.packet.len())
            .map(|index| rebuilt.packet.encoded_payload_length(index))
            .collect::<Vec<_>>()
    );
}

#[test]
fn external_codec_dependent_on_ethernet_macs_uses_the_rebuild_fallback() {
    let mut builder = RegistryBuilder::new();
    builder.module(&BuiltinProtocols).unwrap();
    builder.register_codec(MacSensitiveCodec).unwrap();
    builder
        .bind("ethernet", 0x88b5, "test.mac_sensitive", 200)
        .unwrap();
    let registry = Arc::new(builder.build().unwrap());
    let mut decision = RouteDecision {
        selected_address: None,
        preferred_source: None,
        next_hop: None,
        capability: LinkCapability::Layer2,
        link_type: LinkType::ETHERNET,
        ..route(LinkCapability::Layer2)
    };
    decision.source_mac = Some(MacAddress([2, 0, 0, 0, 0, 1]));
    let interface = decision.interface.clone();
    let ip_lookups = Arc::new(AtomicUsize::new(0));
    let interface_lookups = Arc::new(AtomicUsize::new(0));
    let io = RecordingIo::default();
    let client = Client::new(
        registry,
        InterfaceRoutes {
            decision,
            ip_lookups: Arc::clone(&ip_lookups),
            interface_lookups: Arc::clone(&interface_lookups),
        },
        CountingNeighbors::default(),
        io.clone(),
        TrafficPolicy::default(),
    );
    let mut packet = Packet::new();
    packet
        .push(Ethernet {
            destination: [2, 0, 0, 0, 0, 2],
            source: [0; 6],
            ether_type: WireValue::Exact(0x88b5),
        })
        .push(MacSensitiveLayer);

    let report = client
        .send(
            packet,
            SendOptions {
                plan: PlanOptions {
                    link_mode: LinkMode::Layer2,
                    interface: Some(interface),
                    preferred_source: None,
                },
                ..SendOptions::default()
            },
        )
        .unwrap();

    assert_eq!(ip_lookups.load(Ordering::SeqCst), 0);
    assert_eq!(interface_lookups.load(Ordering::SeqCst), 1);
    assert_eq!(&report.built.bytes[6..12], &[2, 0, 0, 0, 0, 1]);
    assert_eq!(report.built.bytes[14], 2);
    assert_eq!(io.0.lock().unwrap().as_slice(), &[report.built.bytes]);
}

#[test]
fn partial_backend_send_is_a_typed_failure() {
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        PartialIo,
        TrafficPolicy::default(),
    );
    let error = client
        .send(
            packet(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                12345,
                9,
            ),
            SendOptions {
                plan: PlanOptions {
                    link_mode: LinkMode::Layer3,
                    interface: None,
                    preferred_source: None,
                },
                ..SendOptions::default()
            },
        )
        .unwrap_err();
    assert!(matches!(
        error,
        ClientError::Io(LiveIoError::PartialSend { .. })
    ));
}

#[test]
fn changed_post_build_wire_evidence_is_an_invariant_failure() {
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        ChangedWireIo,
        TrafficPolicy::default(),
    );
    let error = client
        .send(
            packet(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                12_345,
                9,
            ),
            SendOptions {
                plan: PlanOptions {
                    link_mode: LinkMode::Layer3,
                    ..PlanOptions::default()
                },
                ..SendOptions::default()
            },
        )
        .unwrap_err();
    assert!(matches!(
        &error,
        ClientError::Io(LiveIoError::InvalidSendEvidence { .. })
    ));
    assert_eq!(error.classification().kind, Kind::Internal);
}
