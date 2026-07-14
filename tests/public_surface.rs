// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;
use std::time::UNIX_EPOCH;

use packetcraftr::{capture, client, error, net, output, packet, protocol, session, workflow};

#[derive(Debug)]
struct NoMatch;

impl packet::matcher::Matcher for NoMatch {
    fn matches(
        &self,
        _request: &packet::Packet,
        _response: &packet::Packet,
    ) -> packet::matcher::Result {
        packet::matcher::Result::no_match()
    }
}

fn assert_packet_extension_contracts<C, M, R>()
where
    C: packet::codec::Codec,
    M: packet::matcher::Matcher,
    R: packet::registry::Module,
{
}

#[test]
fn canonical_packet_and_protocol_namespaces_are_downstream_usable() {
    let mut packet = packet::Packet::new();
    packet.push(packet::layer::Raw::new(vec![0xde, 0xad]));
    let matched = packet::matcher::Matcher::matches(&NoMatch, &packet, &packet);
    assert!(!matched.matched);
    assert!(packet::matcher::Matcher::responder(&NoMatch, &packet, &packet).is_none());

    let registry = protocol::builtin::registry().unwrap();
    assert!(registry.protocol_named("ethernet").is_some());

    // The external-protocol integration test supplies concrete downstream
    // implementations. This signature guards the three intentional extension
    // contracts and their canonical paths as one public surface.
    let _ = assert_packet_extension_contracts::<
        ExternalCodecPlaceholder,
        NoMatch,
        protocol::builtin::Module,
    >;
}

#[derive(Debug)]
struct ExternalCodecPlaceholder;

impl packet::codec::Codec for ExternalCodecPlaceholder {
    fn protocol_id(&self) -> packet::layer::Id {
        packet::layer::Id::new("example.placeholder")
    }

    fn encode(
        &self,
        _layer: &dyn packet::layer::Layer,
        _payload: &[u8],
        _context: &packet::codec::EncodeContext<'_>,
    ) -> Result<packet::codec::Encoded, packet::codec::Error> {
        unreachable!("compile-only public-surface fixture")
    }

    fn decode(
        &self,
        _input: &[u8],
        _context: &packet::codec::DecodeContext<'_>,
    ) -> Result<packet::codec::Decoded, packet::codec::Error> {
        unreachable!("compile-only public-surface fixture")
    }

    fn make_layer(
        &self,
        _fields: &std::collections::BTreeMap<String, packet::field::Value>,
    ) -> Result<Box<dyn packet::layer::Layer>, packet::codec::Error> {
        unreachable!("compile-only public-surface fixture")
    }
}

#[test]
fn canonical_runtime_domain_namespaces_are_downstream_usable() {
    let classification = error::Classification::new("test.public", error::Kind::Packet, None)
        .with_category(error::Category::Validation);
    assert_eq!(classification.kind, error::Kind::Packet);

    let frame =
        capture::Frame::new(UNIX_EPOCH, capture::LinkType::ETHERNET, vec![0xde, 0xad]).unwrap();
    assert_eq!(frame.bytes().as_ref(), &[0xde, 0xad]);
    assert_ne!(capture::LinkType::BSD_RAW, capture::LinkType::RAW);

    let interface = net::interface::Id {
        name: "external0".to_owned(),
        index: 7,
    };
    assert_eq!(interface.index, 7);
    assert_eq!(net::link::MacAddress([2, 0, 0, 0, 0, 7]).0[5], 7);
    assert_eq!(net::link::Mode::default(), net::link::Mode::Auto);

    let limits = session::Limits::default();
    let fragments = session::fragment::Reassembler::new(
        limits.clone(),
        session::fragment::OverlapPolicy::RejectConflicting,
    );
    let tcp = session::tcp::Reassembler::new(limits);
    assert_eq!(fragments.flow_count(), 0);
    assert_eq!(tcp.aggregate_bytes(), 0);

    let target = "192.168.56.10".parse::<client::target::Target>().unwrap();
    let resolved = client::policy::Policy::default()
        .resolve_target(&target, &NeverResolve)
        .unwrap();
    assert_eq!(resolved.selected_address(), Ipv4Addr::new(192, 168, 56, 10));

    assert_eq!(workflow::AddressFamily::Ipv4, workflow::AddressFamily::Ipv4);
    let _ = workflow::scan::Limits::default();
    let _ = workflow::dns::Limits::default();
    let _ = workflow::traceroute::Limits::default();
    let _ = workflow::fuzz::Limits::default();
    let _ = workflow::replay::Limits::default();

    let envelope = output::envelope::Aggregate::success(
        output::contract::Command::Routes,
        output::network::routes::Result { routes: Vec::new() },
        Vec::new(),
    );
    assert_eq!(serde_json::to_value(envelope).unwrap()["mode"], "aggregate");
}

struct NeverResolve;

impl client::target::Resolver for NeverResolve {
    fn resolve(
        &self,
        _hostname: &client::target::Hostname,
        _limit: usize,
    ) -> Result<Vec<std::net::IpAddr>, client::target::Error> {
        panic!("literal IP targets must not invoke hostname resolution")
    }
}
