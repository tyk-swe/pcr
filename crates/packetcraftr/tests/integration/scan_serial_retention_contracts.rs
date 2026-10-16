// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::scanner_fixture::{conditions, providers};

use packetcraftr::{Client, policy::Policy, probe::Endpoint, scan};
use packetcraftr_core::protocol::transport::Tcp;
use packetcraftr_netio::capture::{self, OverflowPolicy};
use providers::{Condition, FamilyAddresses, Io, Providers};
use std::{sync::Arc, time::Duration};

#[derive(Clone, Copy)]
enum Retention {
    Responses,
    Bytes,
}

fn run(retention: Retention, overflow: OverflowPolicy) -> Result<scan::Aggregate, scan::Error> {
    let addresses = FamilyAddresses::IPV4;
    let responder = Arc::new(move |sent: &[u8]| {
        let direct = conditions::respond(Condition::Responsive, addresses, sent);
        if matches!(retention, Retention::Responses) {
            return direct;
        }
        let decoded = packetcraftr_core::decode::Dissector::new(
            packetcraftr_core::protocol::builtin::registry(),
        )
        .decode(
            packetcraftr_core::frame::Frame::new(
                std::time::UNIX_EPOCH,
                packetcraftr_core::frame::LinkType::RAW,
                sent.to_vec(),
            )
            .unwrap(),
            Default::default(),
        )
        .unwrap();
        if decoded.packet.get::<Tcp>().unwrap().destination_port == 80 {
            direct
        } else {
            let mut frames = conditions::respond(Condition::Unrelated, addresses, sent);
            frames.extend(direct);
            frames
        }
    });
    let providers = Providers::new(Io::default(), addresses, responder);
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        Policy::default(),
        providers,
    );
    let request = scan::Request {
        max_in_flight: 1,
        targets: "192.0.2.2"
            .parse::<packetcraftr::target::Target>()
            .unwrap()
            .into(),
        target_sources: Vec::new(),
        endpoints: if matches!(retention, Retention::Responses) {
            vec![Endpoint::Tcp { port: 81 }]
        } else {
            vec![Endpoint::Tcp { port: 80 }, Endpoint::Tcp { port: 81 }]
        },
        tcp_scan: Default::default(),
        sctp_scan: Default::default(),
        discovery: Default::default(),
        udp_payload: Default::default(),
        udp_profiles: Default::default(),
        address_family: Default::default(),
        attempts: 1,
        adaptive: None,
        timeout: Duration::from_millis(20),
        probes_per_second: None,
        limits: scan::Limits {
            max_duration: Duration::from_secs(5),
            ..Default::default()
        },
        route: packetcraftr::route::Options {
            link_mode: packetcraftr_netio::link::Mode::Layer3,
            ..Default::default()
        },
        collection: packetcraftr::exchange::Collection {
            capture: capture::Limits {
                max_frames: 4,
                max_bytes: if matches!(retention, Retention::Bytes) {
                    70
                } else {
                    256
                },
                snap_length: 64,
                overflow_policy: overflow,
            },
            max_responses: if matches!(retention, Retention::Responses) {
                0
            } else {
                4
            },
            max_unmatched_frames: 4,
            ..Default::default()
        },
    };
    let collector = scan::Collector::default();
    let report = client.scan(request, collector.clone())?;
    collector.finish(report)
}

#[test]
fn serial_refused_matched_replies_are_unavailable_under_permissive_retention() {
    for retention in [Retention::Responses, Retention::Bytes] {
        for overflow in [OverflowPolicy::DropNewest, OverflowPolicy::DropOldest] {
            let report = run(retention, overflow).unwrap();
            let refused = report
                .endpoints
                .iter()
                .find(|endpoint| endpoint.port == Some(81))
                .unwrap();
            assert!(matches!(
                refused.probes[0].measurement,
                scan::Measurement::NoReply(scan::Coverage::Incomplete)
            ));
            let inference = refused.inference.as_ref().unwrap();
            assert!(inference.state.is_none());
            assert_eq!(inference.failed, [refused.probes[0].sequence]);
            assert_eq!(report.rtt.lost, 0);
            assert_eq!(report.rtt.unavailable, 1);
            assert_eq!(
                report.stats.capture.dropped_frames, 0,
                "this is local retention refusal, not a native queue drop"
            );
            if matches!(retention, Retention::Bytes) {
                let positive = report
                    .endpoints
                    .iter()
                    .find(|endpoint| endpoint.port == Some(80))
                    .unwrap();
                assert!(matches!(
                    positive.probes[0].measurement,
                    scan::Measurement::Response(_)
                ));
                assert_eq!(report.rtt.received, 1);
            }
        }
    }
}

#[test]
fn serial_default_fail_still_rejects_refused_matched_replies() {
    for retention in [Retention::Responses, Retention::Bytes] {
        assert!(run(retention, OverflowPolicy::Fail).is_err());
    }
}
