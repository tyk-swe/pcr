#![no_main]

use libfuzzer_sys::fuzz_target;
use packetcraftr::dns::{
    MessageLimits, QueryType, decode_response, decode_tcp_frame, encode_query,
};

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_535 {
        return;
    }
    let limits = MessageLimits {
        max_records: 64,
        max_rejected_records: 8,
        ..MessageLimits::default()
    };
    let id = 0x1234;
    let _ = decode_tcp_frame(data, "example.test", QueryType::A, id, limits);
    if decode_response(data, "example.test", QueryType::A, id, limits).is_ok() {
        assert!(decode_response(data, "example.test", QueryType::A, id ^ 1, limits).is_err());
        assert!(decode_response(data, "other.test", QueryType::A, id, limits).is_err());
        assert!(decode_response(data, "example.test", QueryType::Aaaa, id, limits).is_err());
    }
    // Near-valid mutations reach the question/record relations, not just the header.
    let mut message = encode_query("example.test", QueryType::A, id, true)
        .unwrap()
        .to_vec();
    message[2] |= 0x80;
    for pair in data.chunks_exact(2).take(64) {
        let index = usize::from(pair[0]) % message.len();
        message[index] ^= pair[1];
    }
    correlate_endpoints(data.first().copied().unwrap_or(0), &message, limits);
    if decode_response(&message, "example.test", QueryType::A, id, limits).is_ok() {
        message[0] ^= 1;
        assert!(decode_response(&message, "example.test", QueryType::A, id, limits).is_err());
    }
});

fn correlate_endpoints(control: u8, message: &[u8], limits: MessageLimits) {
    use packetcraftr::dns::{Probe, ResponseClassification, classify_response};
    use packetcraftr_core::{
        Packet,
        build::{Builder, Context, Options},
        decode::Dissector,
        frame::{Frame, LinkType},
        layer::Raw,
        protocol::{builtin, network::Ipv4, transport::Udp},
    };
    use std::{
        sync::{Arc, OnceLock},
        time::SystemTime,
    };
    static REGISTRY: OnceLock<Arc<packetcraftr_core::registry::Registry>> = OnceLock::new();
    let registry = REGISTRY.get_or_init(builtin::registry).clone();
    let client = "192.0.2.1".parse().unwrap();
    let server = "198.51.100.2".parse().unwrap();
    let probe = Probe {
        attempt: 1,
        server_address: std::net::IpAddr::V4(server),
        server_port: 53000,
        source_port: 49152,
        transaction_id: 0x1234,
        query_name: "example.test".to_owned(),
        query_type: QueryType::A,
        query: encode_query("example.test", QueryType::A, 0x1234, true).unwrap(),
    };
    let mut sent = probe.packet();
    sent.get_mut::<Ipv4>().unwrap().source = client;
    let mut response = Packet::new();
    response.push(Ipv4 {
        source: if control & 1 != 0 {
            "203.0.113.9".parse().unwrap()
        } else {
            server
        },
        destination: if control & 2 != 0 {
            "192.0.2.9".parse().unwrap()
        } else {
            client
        },
        ..Ipv4::default()
    });
    response.push(Udp {
        source_port: probe.server_port + u16::from(control & 4 != 0),
        destination_port: probe.source_port + u16::from(control & 8 != 0),
        ..Udp::default()
    });
    response.push(Raw::new(message.to_vec()));
    let built = Builder::new(registry.clone())
        .build(response, Context::default(), Options::default())
        .unwrap();
    let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::IPV4, built.bytes).unwrap();
    let decoded = Dissector::new(registry.clone())
        .decode(frame, Default::default())
        .unwrap();
    let accepted = matches!(
        classify_response(&registry, &probe, &sent, &decoded, limits),
        Some(ResponseClassification::Response(_))
    );
    let expected = control & 15 == 0
        && decode_response(message, "example.test", QueryType::A, 0x1234, limits).is_ok();
    assert_eq!(
        accepted, expected,
        "only the actual attempt endpoints and valid question/ID can be accepted"
    );
}
