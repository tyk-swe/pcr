// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
//! One representative `stats` analysis report shared by the conversion and
//! schema-conformance test binaries; per-test differences are parameters.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr_core::analysis::reassembly::ip::{
    DatagramKey, IncompleteDatagram, IncompleteReason, Ipv4DatagramKey, Ipv6DatagramKey,
};
use packetcraftr_core::analysis::scope::Interner;
use packetcraftr_core::analysis::stats::{
    ConversationStat, EndpointStat, IoBucketStat, PortStat, ProtocolStat, Report,
};
use packetcraftr_core::analysis::{
    IpCounters, IpDatagramOutcome, IpFamilyCounters, IpReassemblyReport, StreamTransport,
};

/// A report exercising every statistics table. The conversation addresses and
/// the incomplete outcome's known final length vary per test.
pub(crate) fn report(
    address_a: Ipv4Addr,
    address_b: Ipv4Addr,
    known_final_length: Option<usize>,
) -> Report {
    let first = UNIX_EPOCH + Duration::from_secs(5);
    let last = first + Duration::from_millis(3_250);
    let mut scopes = Interner::new();
    let scope = scopes
        .intern(None, Vec::new())
        .expect("representative scope fits");
    Report {
        clock: Default::default(),
        io_origin: Some(first),
        io_underflow_frames: 0,
        interval: Duration::from_secs(2),
        frames: 7,
        bytes: 321,
        first_timestamp: Some(first),
        last_timestamp: Some(last),
        protocols: vec![ProtocolStat {
            protocol: "ipv4".to_owned(),
            frames: 7,
            bytes: 321,
        }],
        conversations: vec![ConversationStat {
            scope: scopes.definition(scope).unwrap().clone(),
            transport: StreamTransport::Tcp,
            stream: 4,
            address_a: IpAddr::V4(address_a),
            port_a: 40_000,
            address_b: IpAddr::V4(address_b),
            port_b: 443,
            frames_a_to_b: 3,
            bytes_a_to_b: 120,
            frames_b_to_a: 4,
            bytes_b_to_a: 201,
            first_timestamp: first,
            last_timestamp: last,
        }],
        endpoints: vec![EndpointStat {
            address: IpAddr::V4(address_a),
            tx_frames: 3,
            tx_bytes: 120,
            rx_frames: 4,
            rx_bytes: 201,
        }],
        ports: vec![PortStat {
            transport: StreamTransport::Udp,
            port: 53,
            frames: 2,
            bytes: 80,
        }],
        io: vec![IoBucketStat {
            offset: Duration::from_secs(2),
            frames: 5,
            bytes: 240,
        }],
        ip_reassembly: IpReassemblyReport {
            counters: IpCounters {
                ipv4: IpFamilyCounters {
                    physical_fragments: 3,
                    admitted_fragments: 3,
                    completing_fragments: 1,
                    completed_datagrams: 1,
                    overlap_bytes: 2,
                    derived_datagram_bytes: 44,
                    derived_payload_bytes: 24,
                    ..IpFamilyCounters::default()
                },
                ipv6: IpFamilyCounters {
                    physical_fragments: 1,
                    admitted_fragments: 1,
                    incomplete_datagrams: 1,
                    end_of_capture_datagrams: 1,
                    ..IpFamilyCounters::default()
                },
            },
            outcomes: vec![
                IpDatagramOutcome::Completed {
                    key: DatagramKey::Ipv4(Ipv4DatagramKey {
                        scope,
                        source: Ipv4Addr::new(192, 0, 2, 1),
                        destination: Ipv4Addr::new(198, 51, 100, 2),
                        identification: 42,
                        protocol: 17,
                    }),
                    fragment_count: 3,
                    unique_bytes: 24,
                    final_payload_length: 24,
                    datagram_bytes: 44,
                    duplicate_fragments: 1,
                    overlap_bytes: 2,
                },
                IpDatagramOutcome::Incomplete(IncompleteDatagram {
                    key: DatagramKey::Ipv6(Ipv6DatagramKey {
                        scope,
                        source: Ipv6Addr::LOCALHOST,
                        destination: "2001:db8::2".parse().expect("documentation address"),
                        identification: 7,
                    }),
                    reason: IncompleteReason::EndOfCapture,
                    fragment_count: 1,
                    unique_bytes: 16,
                    known_final_length,
                    duplicate_fragments: 0,
                    overlap_bytes: 0,
                }),
            ],
            outcomes_omitted: 2,
        },
        interfaces: vec![
            packetcraftr_core::analysis::pcap::Interface {
                link_type: packetcraftr_core::frame::LinkType(1),
                snap_len: 65_535,
                timestamp_resolution:
                    packetcraftr_core::analysis::pcap::TimestampResolution::Decimal(6),
                timestamp_offset: 0,
            },
            packetcraftr_core::analysis::pcap::Interface {
                link_type: packetcraftr_core::frame::LinkType(276),
                snap_len: 9_000,
                timestamp_resolution:
                    packetcraftr_core::analysis::pcap::TimestampResolution::Decimal(9),
                timestamp_offset: 0,
            },
        ],
    }
}
