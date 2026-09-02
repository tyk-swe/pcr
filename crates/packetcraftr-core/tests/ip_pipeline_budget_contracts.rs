// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contracts for the aggregate reassembly budget and expiry ordering.

mod common;

use common::ip_fragments::{
    cascading_vxlan_tcp_frames, ipv4_fragments, ipv4_protocol_fragment_frame, reader_with_link_type,
};
use common::registry;
use packetcraftr_core::analysis::reassembly::ip::{
    IncompleteDatagram, IncompleteReason, ResourceError,
};
use packetcraftr_core::analysis::{
    IpDatagramOutcome, IpEvent, IpEventRecord, Limits, Options, run_with_ip_events,
};
use packetcraftr_core::error::Classified;
use packetcraftr_core::frame::LinkType;
use std::time::{Duration, SystemTime};

#[test]
fn derived_cascade_bytes_share_the_aggregate_reassembly_budget() {
    let registry = registry();
    let frames = cascading_vxlan_tcp_frames(&registry);
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames[..2]);
    let limit = 26_200;
    let result = packetcraftr_core::analysis::run(
        &mut capture,
        registry,
        &Options {
            limits: Limits {
                max_ip_reassembly_bytes: limit,
                ..Limits::default()
            },
            ..Options::default()
        },
        |_| Ok(()),
    );

    assert!(matches!(
        result,
        Err(packetcraftr_core::analysis::Error::IpReassembly {
            number: 2,
            source: packetcraftr_core::analysis::reassembly::ip::Error::Resource(
                ResourceError::AggregateMemoryLimit { limit: 26_200 }
            )
        })
    ));
}

#[test]
fn derived_decode_metadata_shares_the_aggregate_reassembly_budget() {
    let registry = registry();
    let frames = ipv4_fragments(&registry);
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames);
    let result = packetcraftr_core::analysis::run(
        &mut capture,
        registry,
        &Options {
            limits: Limits {
                max_ip_reassembly_bytes: 5_000,
                ..Limits::default()
            },
            ..Options::default()
        },
        |_| Ok(()),
    );

    assert!(matches!(
        result,
        Err(packetcraftr_core::analysis::Error::IpReassembly {
            number: 2,
            source: packetcraftr_core::analysis::reassembly::ip::Error::Resource(
                ResourceError::AggregateMemoryLimit { limit: 5_000 }
            )
        })
    ));
}

#[test]
fn budget_reduced_derived_layer_limit_keeps_resource_classification() {
    let registry = registry();
    let frames = cascading_vxlan_tcp_frames(&registry);
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames[..2]);
    let error = packetcraftr_core::analysis::run(
        &mut capture,
        registry,
        &Options {
            limits: Limits {
                max_ip_reassembly_bytes: 10_000,
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
                ResourceError::AggregateMemoryLimit { limit: 10_000 }
            )
        }
    ));
    assert_eq!(
        error.classification().code,
        "policy.analysis_resource_limit"
    );
}

#[test]
fn idle_expiry_is_delivered_before_a_failing_fragment_push() {
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
        max_ip_bytes_per_datagram: 8,
        ip_idle_expiry: Duration::from_secs(1),
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
        result.is_err(),
        "the second fragment must exceed its byte limit"
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
