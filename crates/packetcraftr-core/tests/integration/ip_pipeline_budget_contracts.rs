// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;

use common::ip_fragments::{
    cascading_vxlan_tcp_frames, ipv4_protocol_fragment_frame, reader_with_link_type,
};
use common::registry;
use packetcraftr_core::analysis::reassembly::ip::{IncompleteDatagram, IncompleteReason, Resource};
use packetcraftr_core::analysis::{
    IpDatagramOutcome, IpEvent, IpEventRecord, Limits, Options, run_with_ip_events,
};
use packetcraftr_core::error::Classified;
use packetcraftr_core::frame::LinkType;
use std::time::{Duration, SystemTime};

#[test]
fn budget_reduced_resource_class() {
    let registry = registry();
    let frames = cascading_vxlan_tcp_frames(&registry);
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames[..2]);
    let error = packetcraftr_core::analysis::run(
        &mut capture,
        registry,
        &Options {
            limits: Limits {
                ip: packetcraftr_core::analysis::reassembly::ip::Limits {
                    max_aggregate_bytes: 10_000,
                    ..packetcraftr_core::analysis::reassembly::ip::Limits::default()
                },
                ..Limits::default()
            },
            ..Options::default()
        },
        |_| Ok(()),
    )
    .expect_err("the derived VXLAN stack exceeds its budget-reduced layer cap");

    assert!(matches!(
        &error,
        packetcraftr_core::analysis::Error::IpReassembly {
            number: 2,
            source: packetcraftr_core::analysis::reassembly::ip::Error::Resource(
                Resource::AggregateMemoryLimit { limit: 10_000 }
            )
        }
    ));
    assert_eq!(
        error.classification().code,
        "policy.analysis_resource_limit"
    );
}

#[test]
fn idle_expiry_before_frag_push() {
    let registry = registry();
    let first_payload = [1_u8; 8];
    let failing_payload = [2_u8; 8];
    let frames = [
        ipv4_protocol_fragment_frame(
            &registry,
            SystemTime::UNIX_EPOCH,
            1,
            17,
            0,
            true,
            &first_payload,
        ),
        ipv4_protocol_fragment_frame(
            &registry,
            SystemTime::UNIX_EPOCH + Duration::from_secs(2),
            2,
            17,
            1,
            true,
            &failing_payload,
        ),
    ];
    let limits = Limits {
        ip: packetcraftr_core::analysis::reassembly::ip::Limits {
            max_bytes_per_datagram: 8,
            idle_expiry: Duration::from_secs(1),
            ..packetcraftr_core::analysis::reassembly::ip::Limits::default()
        },
        ..Limits::default()
    };
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames);
    let mut events = Vec::new();
    let result = run_with_ip_events(
        &mut capture,
        registry,
        &Options {
            limits,
            ..Options::default()
        },
        |event| {
            events.push(event);
            Ok(())
        },
        |_| Ok(()),
    );

    assert!(
        matches!(
            result,
            Err(packetcraftr_core::analysis::Error::IpReassembly {
                number: 2,
                source: packetcraftr_core::analysis::reassembly::ip::Error::Resource(
                    Resource::DatagramByteLimit { limit: 8 }
                )
            })
        ),
        "the second fragment must exceed its byte limit: {result:?}"
    );
    assert!(matches!(
        events.as_slice(),
        [IpEventRecord {
            number: 2,
            event: IpEvent::Outcome(IpDatagramOutcome::Incomplete(IncompleteDatagram {
                reason: IncompleteReason::IdleExpired,
                ..
            }))
        }]
    ));
}
