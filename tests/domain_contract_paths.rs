// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};

use packetcraftr::domain::{command, event, net, policy, report, request, spec, transmission};

#[test]
fn shared_contracts_are_public_from_domain() {
    let request = request::PacketRequest::default();
    let _command = command::EngineCommand::DryRun(request.clone());
    let _dns = command::DnsRequest::default();
    let _policy = policy::TrafficPolicy::default();
    let _plan =
        policy::TrafficPlan::new(policy::TrafficMode::Send, policy::TargetScope::Unspecified);
    let _spec = spec::PacketSpec::from_request(&request);
    let _label = event::ProtocolLabel::Unknown;
    let _mac = net::MacAddress::new([0, 1, 2, 3, 4, 5]);
    let _ethertype = net::EtherType::IPV4;
    let _protocol = net::IpProtocol(17);
    let _mode = transmission::PlanningMode::DryRun;
    let _transmission_protocol = transmission::TransmissionProtocol(17);
    let _link_type = transmission::TransmissionLinkType::Ethernet.as_str();
}

#[test]
fn mac_address_parses_and_displays_canonical_lowercase_hex() {
    let colon = "AA:bb:0C:dd:eE:fF"
        .parse::<net::MacAddress>()
        .expect("colon-separated MAC should parse");
    let hyphen = "aa-bb-0c-dd-ee-ff"
        .parse::<net::MacAddress>()
        .expect("hyphen-separated MAC should parse");

    assert_eq!(colon, hyphen);
    assert_eq!(colon.octets(), [0xaa, 0xbb, 0x0c, 0xdd, 0xee, 0xff]);
    assert_eq!(colon.to_string(), "aa:bb:0c:dd:ee:ff");
}

#[test]
fn mac_address_rejects_invalid_input() {
    for value in [
        "",
        "aa:bb:cc:dd:ee",
        "aa:bb:cc:dd:ee:ff:00",
        "aa:bb:cc:dd:ee:gg",
        "a:bb:cc:dd:ee:ff",
        "aa:bb:cc:dd:ee:",
    ] {
        assert!(
            value.parse::<net::MacAddress>().is_err(),
            "expected invalid MAC address to be rejected: {value}"
        );
    }
}

#[test]
fn preflight_view_can_be_built_from_public_transmission_contracts() {
    let destination = Ipv4Addr::new(192, 0, 2, 1);
    let source = Ipv4Addr::new(192, 0, 2, 2);
    let plan = transmission::TransmissionPlan {
        frames: vec![vec![0; 42]],
        link_type: transmission::TransmissionLinkType::Ethernet,
        transmit: spec::TransmissionSpec::default(),
        destination: transmission::TransmissionTarget::Ipv4(destination),
        interface_name: "eth0".to_string(),
        selection: transmission::TransmissionSelection {
            selected_interface: "eth0".to_string(),
            interface_reason: transmission::InterfaceSelectionReason::ExplicitInterface,
            source_ip: IpAddr::V4(source),
            source_reason: transmission::SourceSelectionReason::ExplicitSourceIp,
            destination_ip: IpAddr::V4(destination),
            destination_reason: transmission::DestinationSelectionReason::TargetLiteral,
        },
        protocol: transmission::TransmissionProtocol(17),
        summary: transmission::TransmissionSummary {
            payload_len: 0,
            largest_frame_len: 42,
            frame_count: 1,
            transport: "udp",
        },
        logging: spec::LoggingSpec::default(),
        mode: transmission::PlanningMode::DryRun,
        policy: policy::TransmissionPolicy::default(),
    };

    let view = report::PreflightView::from_transmission_plan(&plan)
        .expect("valid transmission plan should produce a preflight view");

    assert_eq!(view.destination, "192.0.2.1");
    assert_eq!(view.selected_destination_ip, "192.0.2.1");
    assert_eq!(view.interface, "eth0");
    assert_eq!(view.source_ip, "192.0.2.2");
    assert_eq!(view.mode, "L2");
    assert_eq!(view.transport, "udp");
    assert_eq!(view.total_emitted_units, Some(1));
}
