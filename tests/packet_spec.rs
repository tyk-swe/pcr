// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use packetcraftr::cli::{
    IpOptions, Layer2Options, OneShotOptions, PayloadOptions, TransportCommand, TransportOptions,
    UdpOptions,
};
use packetcraftr::engine::request::PacketRequest;
use packetcraftr::engine::spec::{
    PacketSpec, PayloadSource, SpecError, TargetAddress, TransportSpec,
};
use pnet::datalink::MacAddr;
use pnet::packet::ethernet::EtherTypes;

fn packet_spec_from_options(options: &OneShotOptions) -> Result<PacketSpec, SpecError> {
    let request = PacketRequest::from(options);
    PacketSpec::from_request(&request)
}

#[test]
fn ipv4_udp_minimal_options_convert_to_packet_spec() {
    let mut options = OneShotOptions {
        destination: Some("198.51.100.10".to_string()),
        layer2: Layer2Options {
            source_mac: Some("aa:bb:cc:dd:ee:01".to_string()),
            destination_mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            ethertype: Some("ipv4".to_string()),
            vlan: Default::default(),
        },
        transport: TransportOptions {
            source_port: Some(5353),
            destination_port: Some(53),
            command: Some(TransportCommand::Udp(UdpOptions::default())),
        },
        payload: PayloadOptions {
            data_hex: Some("de ad be ef".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    options.ip.source_ip = Some("198.51.100.5".to_string());
    options.ip.destination_ip = Some("198.51.100.10".to_string());

    let spec = packet_spec_from_options(&options).expect("packet spec should build");

    match spec.target.address {
        Some(TargetAddress::Ip(IpAddr::V4(addr))) => {
            assert_eq!(addr, Ipv4Addr::new(198, 51, 100, 10));
        }
        other => panic!("unexpected destination: {other:?}"),
    }

    assert_eq!(
        spec.layer2.source,
        Some(MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01))
    );
    assert_eq!(
        spec.layer2.destination,
        Some(MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff))
    );
    assert_eq!(spec.layer2.ethertype, Some(EtherTypes::Ipv4.0));

    let ip = spec.ip.expect("ip spec should be present");
    assert_eq!(ip.source, Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5))));
    assert_eq!(
        ip.destination,
        Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)))
    );

    match spec.transport {
        TransportSpec::Udp(udp) => {
            assert_eq!(udp.source_port, Some(5353));
            assert_eq!(udp.destination_port, Some(53));
        }
        other => panic!("unexpected transport spec: {other:?}"),
    }

    assert!(matches!(spec.payload.source, PayloadSource::Hex(ref hex) if hex == "de ad be ef"));
    assert!(!spec.transmit.is_layer3());
}

#[test]
fn ipv6_target_without_layer2_defaults_to_auto_layer3() {
    let options = OneShotOptions {
        destination: Some("2001:db8::100".to_string()),
        transport: TransportOptions {
            command: Some(TransportCommand::Udp(UdpOptions::default())),
            destination_port: Some(5353),
            ..Default::default()
        },
        ..Default::default()
    };

    let spec = packet_spec_from_options(&options).expect("packet spec should build");

    match spec.target.address {
        Some(TargetAddress::Ip(IpAddr::V6(addr))) => {
            assert_eq!(addr, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x100));
        }
        other => panic!("unexpected destination: {other:?}"),
    }
    assert!(spec.layer2.source.is_none());
    assert!(spec.layer2.destination.is_none());
    assert!(spec.transmit.is_layer3());
    assert!(spec.transmit.auto_layer3);
    assert!(!spec.transmit.ipv6_nd);
}

#[test]
fn explicit_destination_ip_takes_precedence_over_destination_string() {
    let options = OneShotOptions {
        destination: Some("2001:db8::1".to_string()),
        ip: IpOptions {
            destination_ip: Some("192.0.2.10".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    let spec = packet_spec_from_options(&options).expect("packet spec should build");

    match spec.target.address {
        Some(TargetAddress::Ip(IpAddr::V4(addr))) => {
            assert_eq!(addr, Ipv4Addr::new(192, 0, 2, 10));
        }
        other => panic!("unexpected destination: {other:?}"),
    }

    let ip = spec.ip.expect("ip spec should be present");
    assert_eq!(
        ip.destination,
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
    );
    assert!(matches!(spec.transport, TransportSpec::Icmp(_)));
}

#[test]
fn prefer_ipv6_falls_back_to_ipv6_transport_without_destination() {
    let options = OneShotOptions {
        ip: IpOptions {
            prefer_ipv6: Some(true),
            ..Default::default()
        },
        ..Default::default()
    };

    let spec = packet_spec_from_options(&options).expect("packet spec should build");

    assert!(matches!(spec.transport, TransportSpec::Icmpv6(_)));
    assert!(spec.transmit.auto_layer3);
}
