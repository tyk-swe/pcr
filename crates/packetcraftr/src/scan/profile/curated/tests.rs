// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use packetcraftr_core::document::udp_profiles::{Config, Payload, ResponseCheck};

use super::{CURATED_UDP_PAYLOADS_VERSION, bundled, data_set, merge};
use crate::probe::{ProbeEndpoint, Transport};
use crate::scan::catalog;
use crate::scan::profile::{Status, UdpProfile};

const SEQUENCE: u64 = 7;

/// A reply each curated check is written to accept.
fn conforming_reply(port: u16, query: &[u8]) -> Vec<u8> {
    let mut reply = match port {
        // A DNS response echoes the ID and question with QR set.
        53 | 5353 => {
            let mut reply = query.to_vec();
            reply[2] |= 0x80;
            return reply;
        }
        111 => [0x5043_0001u32, 1, 0, 0, 0, 0]
            .iter()
            .flat_map(|word| word.to_be_bytes())
            .collect(),
        123 => [vec![0x24], vec![0; 47]].concat(),
        161 => vec![0x30, 0x00],
        3478 => [0x0101_0000u32, 0x2112_a442]
            .iter()
            .flat_map(|word| word.to_be_bytes())
            .collect(),
        5683 => vec![0x60, 0x45, 0x50, 0x43],
        _ => panic!("no conforming reply for curated port {port}"),
    };
    if port == 3478 {
        reply.extend_from_slice(b"PacketcraftR");
    }
    reply
}

#[test]
fn provenance_names_the_published_version() {
    let manifest = include_str!("../../../../data/udp-payloads.provenance.yaml");
    assert!(
        manifest
            .lines()
            .any(|line| line == "  name: \"udp-payloads\"")
    );
    assert!(
        manifest
            .lines()
            .any(|line| line == format!("  version: \"{CURATED_UDP_PAYLOADS_VERSION}\""))
    );
    assert!(
        manifest
            .lines()
            .any(|line| line == "  review_outcome: \"accepted\"")
    );
    assert_eq!(data_set().version, CURATED_UDP_PAYLOADS_VERSION);
}

#[test]
fn every_curated_profile_is_a_named_catalog_port_with_a_working_check() {
    assert_eq!(bundled().len(), 7);
    for (port, profile) in bundled() {
        assert!(profile.name().starts_with("curated/"), "{}", profile.name());
        assert!(
            catalog::hint(Transport::Udp, *port).is_some(),
            "curated UDP port {port} has no catalog entry"
        );
        let query = profile.payload(SEQUENCE);
        assert_eq!(query.len(), profile.payload_length());
        let reply = conforming_reply(*port, &query);
        let evidence = profile.evaluate(&query, &reply);
        assert_eq!(
            evidence.status,
            Status::Confirmed,
            "{port}: {}",
            evidence.reason
        );
    }
}

#[test]
fn byte_checks_reject_a_reflected_request() {
    // Echo-style responders reflect the request; a check that accepted its
    // own request would confirm nothing.
    for port in [111, 123, 3478, 5683] {
        let profile = &bundled()[&port];
        let query = profile.payload(SEQUENCE);
        assert_eq!(
            profile.evaluate(&query, &query).status,
            Status::Rejected,
            "{port}"
        );
    }
}

#[test]
fn operator_profiles_win_and_only_planned_udp_ports_receive_curated_payloads() {
    let operator = Arc::new(
        UdpProfile::new(Config {
            name: "operator/ntp".to_owned(),
            request: Payload::Bytes {
                data: Bytes::from_static(b"operator"),
            },
            response: ResponseCheck::Any {},
        })
        .unwrap(),
    );
    let endpoints = [
        ProbeEndpoint::Udp { port: 123 },
        ProbeEndpoint::Udp { port: 53 },
        ProbeEndpoint::Udp { port: 9 },
        // A TCP endpoint sharing a curated port number receives nothing.
        ProbeEndpoint::Tcp { port: 161 },
    ];
    let merged = merge(BTreeMap::from([(123, Arc::clone(&operator))]), &endpoints);
    assert_eq!(merged.overridden, [123]);
    assert_eq!(merged.applied, [53]);
    assert_eq!(merged.profiles.len(), 2);
    assert!(Arc::ptr_eq(&merged.profiles[&123], &operator));
    assert_eq!(merged.profiles[&53].name(), "curated/dns-root-ns");
    assert!(!merged.profiles.contains_key(&161));
}
