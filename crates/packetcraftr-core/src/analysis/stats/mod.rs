// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Aggregate capture statistics computed over the analysis pipeline.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::protocol::network::{Ipv4, Ipv6};

use crate::analysis::Error;
use crate::analysis::IpReassemblyReport;
use crate::analysis::conversation_index::CanonicalFlow;
use crate::analysis::pipeline::FrameRecord;
use crate::analysis::reassembly::tcp::ScopedFlowKey;

mod report;
pub use report::{
    ConversationStat, EndpointStat, IoBucketStat, PortStat, ProtocolStat, Report, TransportKind,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Tally {
    frames: u64,
    bytes: u64,
}

impl Tally {
    fn add(&mut self, bytes: u64) {
        self.frames = self.frames.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct DirectionalTally {
    a_to_b: Tally,
    b_to_a: Tally,
}

#[derive(Clone, Debug)]
struct ConversationState {
    flow: CanonicalFlow,
    tally: DirectionalTally,
    first_timestamp: SystemTime,
    last_timestamp: SystemTime,
}

#[derive(Clone, Copy, Debug, Default)]
struct EndpointTally {
    tx: Tally,
    rx: Tally,
}

/// Accumulates statistics from analysis frame records.
///
/// Every physical table is keyed by values a frame carries, so retained state
/// grows with distinct keys and never faster than the pipeline's frame budget;
/// conversations are additionally bounded by the pipeline's flow budget,
/// which fails closed before this collector would see a new index. Bounded,
/// capture-global fragment accounting is attached only when the pass finishes.
#[derive(Debug)]
pub struct Collector {
    interval: Duration,
    frames: u64,
    bytes: u64,
    first_timestamp: Option<SystemTime>,
    last_timestamp: Option<SystemTime>,
    io_origin: Option<SystemTime>,
    protocols: BTreeMap<String, Tally>,
    conversations: BTreeMap<(TransportKind, u64), ConversationState>,
    endpoints: BTreeMap<IpAddr, EndpointTally>,
    ports: BTreeMap<(TransportKind, u16), Tally>,
    io: BTreeMap<u64, Tally>,
}

impl Collector {
    /// Creates a collector with the given I/O bucket width.
    pub fn new(interval: Duration) -> Result<Self, Error> {
        if interval.is_zero() {
            return Err(Error::InvalidLimit {
                field: "interval",
                value: 0,
                reason: "must be non-zero",
            });
        }
        Ok(Self {
            interval,
            frames: 0,
            bytes: 0,
            first_timestamp: None,
            last_timestamp: None,
            io_origin: None,
            protocols: BTreeMap::new(),
            conversations: BTreeMap::new(),
            endpoints: BTreeMap::new(),
            ports: BTreeMap::new(),
            io: BTreeMap::new(),
        })
    }

    /// Folds one matched frame into every table.
    pub fn observe(&mut self, record: &FrameRecord<'_>) -> Result<(), Error> {
        let bytes = u64::from(record.decoded.frame.captured_length());
        let timestamp = record
            .decoded
            .frame
            .timestamp
            .ok_or(Error::TimestampUnavailable {
                number: record.number,
            })?;
        self.frames = self.frames.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
        self.observe_time(timestamp, bytes);

        // Protocol presence: once per distinct protocol per frame.
        let mut seen: Vec<&str> = Vec::new();
        for layer in record.decoded.packet.iter() {
            let name = layer.protocol_id().as_str();
            if !seen.contains(&name) {
                seen.push(name);
            }
        }
        for name in seen {
            self.protocols
                .entry(name.to_owned())
                .or_default()
                .add(bytes);
        }

        // Count innermost-network endpoints as sender and receiver.
        if let Some((source, destination)) = innermost_network(record) {
            self.endpoints.entry(source).or_default().tx.add(bytes);
            self.endpoints.entry(destination).or_default().rx.add(bytes);
        }

        // Use pipeline-assigned stream IDs for stable conversation and port stats.
        if let (Some(stream), Some(flow)) = (record.tcp_stream, record.tcp_flow) {
            self.record_conversation(TransportKind::Tcp, stream, flow, bytes, timestamp);
        }
        if let (Some(stream), Some(flow)) = (record.udp_stream, record.udp_flow) {
            self.record_conversation(TransportKind::Udp, stream, flow, bytes, timestamp);
        }
        Ok(())
    }

    fn observe_time(&mut self, timestamp: SystemTime, bytes: u64) {
        let origin = *self.io_origin.get_or_insert(timestamp);
        self.first_timestamp = Some(
            self.first_timestamp
                .map_or(timestamp, |first| first.min(timestamp)),
        );
        self.last_timestamp = Some(match self.last_timestamp {
            Some(last) => last.max(timestamp),
            None => timestamp,
        });

        // Bucket timestamps before the capture origin at zero.
        let offset = timestamp.duration_since(origin).unwrap_or(Duration::ZERO);
        #[expect(
            clippy::arithmetic_side_effects,
            reason = "the divisor is forced to at least 1 by `max(1)`"
        )]
        let bucket = offset.as_nanos() / self.interval.as_nanos().max(1);
        self.io
            .entry(u64::try_from(bucket).unwrap_or(u64::MAX))
            .or_default()
            .add(bytes);
    }

    fn record_conversation(
        &mut self,
        transport: TransportKind,
        stream: u64,
        flow: &ScopedFlowKey,
        bytes: u64,
        timestamp: SystemTime,
    ) {
        let canonical = CanonicalFlow::from_flow(flow);
        let state = self
            .conversations
            .entry((transport, stream))
            .or_insert_with(|| ConversationState {
                flow: canonical,
                tally: DirectionalTally::default(),
                first_timestamp: timestamp,
                last_timestamp: timestamp,
            });
        if (flow.flow.source, flow.flow.source_port) == state.flow.first {
            state.tally.a_to_b.add(bytes);
        } else {
            state.tally.b_to_a.add(bytes);
        }
        state.first_timestamp = state.first_timestamp.min(timestamp);
        state.last_timestamp = state.last_timestamp.max(timestamp);

        // Each distinct port a frame touches counts once.
        let mut ports = [flow.flow.source_port, flow.flow.destination_port];
        ports.sort_unstable();
        let distinct = if ports[0] == ports[1] {
            &ports[..1]
        } else {
            &ports[..]
        };
        for port in distinct {
            self.ports.entry((transport, *port)).or_default().add(bytes);
        }
    }

    /// Finishes the pass and attaches capture-global IP fragment accounting.
    ///
    /// Physical frame and byte totals remain those observed by this collector;
    /// derived datagram and payload bytes live only in `ip_reassembly`.
    pub fn finish(self, ip_reassembly: IpReassemblyReport) -> Report {
        let mut protocols = self
            .protocols
            .into_iter()
            .map(|(protocol, tally)| ProtocolStat {
                protocol,
                frames: tally.frames,
                bytes: tally.bytes,
            })
            .collect::<Vec<_>>();
        protocols.sort_by(|left, right| {
            right
                .frames
                .cmp(&left.frames)
                .then_with(|| left.protocol.cmp(&right.protocol))
        });

        let conversations = self
            .conversations
            .into_iter()
            .map(|((transport, stream), state)| ConversationStat {
                transport,
                stream,
                address_a: state.flow.first.0,
                port_a: state.flow.first.1,
                address_b: state.flow.second.0,
                port_b: state.flow.second.1,
                frames_a_to_b: state.tally.a_to_b.frames,
                bytes_a_to_b: state.tally.a_to_b.bytes,
                frames_b_to_a: state.tally.b_to_a.frames,
                bytes_b_to_a: state.tally.b_to_a.bytes,
                first_timestamp: state.first_timestamp,
                last_timestamp: state.last_timestamp,
            })
            .collect();

        let endpoints = self
            .endpoints
            .into_iter()
            .map(|(address, tally)| EndpointStat {
                address,
                tx_frames: tally.tx.frames,
                tx_bytes: tally.tx.bytes,
                rx_frames: tally.rx.frames,
                rx_bytes: tally.rx.bytes,
            })
            .collect();

        let ports = self
            .ports
            .into_iter()
            .map(|((transport, port), tally)| PortStat {
                transport,
                port,
                frames: tally.frames,
                bytes: tally.bytes,
            })
            .collect();

        let interval = self.interval;
        let io = self
            .io
            .into_iter()
            .map(|(bucket, tally)| IoBucketStat {
                // Compute offsets in u128; saturate only when converting to Duration.
                offset: duration_from_nanos_saturating(
                    interval.as_nanos().saturating_mul(u128::from(bucket)),
                ),
                frames: tally.frames,
                bytes: tally.bytes,
            })
            .collect();

        Report {
            interval,
            frames: self.frames,
            bytes: self.bytes,
            first_timestamp: self.first_timestamp,
            last_timestamp: self.last_timestamp,
            protocols,
            conversations,
            endpoints,
            ports,
            io,
            ip_reassembly,
        }
    }
}

fn duration_from_nanos_saturating(nanoseconds: u128) -> Duration {
    const NANOS_PER_SECOND: u128 = 1_000_000_000;
    let Ok(seconds) = u64::try_from(nanoseconds / NANOS_PER_SECOND) else {
        return Duration::MAX;
    };
    let subsecond = u32::try_from(nanoseconds % NANOS_PER_SECOND)
        .expect("nanosecond remainder is less than one billion");
    Duration::new(seconds, subsecond)
}

/// The innermost IP layer's addresses, when the frame has any.
fn innermost_network(record: &FrameRecord<'_>) -> Option<(IpAddr, IpAddr)> {
    let mut network = None;
    for layer in record.decoded.packet.iter() {
        if let Some(ipv4) = layer.as_any().downcast_ref::<Ipv4>() {
            network = Some((ipv4.source.into(), ipv4.destination.into()));
        } else if let Some(ipv6) = layer.as_any().downcast_ref::<Ipv6>() {
            network = Some((ipv6.source.into(), ipv6.destination.into()));
        }
    }
    network
}
