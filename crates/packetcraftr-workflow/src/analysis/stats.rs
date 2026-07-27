// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

/// Aggregate capture statistics computed over the analysis pipeline.
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use super::session_index::{CanonicalFlow, tcp_segment, udp_flow};
use super::{AnalysisError, FlowKey, FrameRecord, Ipv4, Ipv6};

/// Which transport a conversation or port tally belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransportKind {
    Tcp,
    Udp,
}

impl TransportKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Frame and byte pair used by every tally.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    pub frames: u64,
    pub bytes: u64,
}

impl Tally {
    fn add(&mut self, bytes: u64) {
        self.frames += 1;
        self.bytes += bytes;
    }
}

/// One protocol's presence across the matched frames.
///
/// A frame counts once per protocol it contains, however many times the
/// protocol occurs in its stack, and contributes its whole captured length,
/// so a tunnelled frame is visible in full under both its encapsulations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolStat {
    pub protocol: String,
    pub frames: u64,
    pub bytes: u64,
}

/// One conversation with per-direction tallies.
///
/// Endpoint A is the canonically smaller endpoint, so the same conversation
/// renders identically whichever direction was captured first; `stream` is
/// the index the analysis pipeline assigned, shared with display filters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversationStat {
    pub transport: TransportKind,
    pub stream: u64,
    pub address_a: IpAddr,
    pub port_a: u16,
    pub address_b: IpAddr,
    pub port_b: u16,
    pub frames_a_to_b: u64,
    pub bytes_a_to_b: u64,
    pub frames_b_to_a: u64,
    pub bytes_b_to_a: u64,
    pub first_timestamp: SystemTime,
    pub last_timestamp: SystemTime,
}

impl ConversationStat {
    pub fn duration(&self) -> Duration {
        self.last_timestamp
            .duration_since(self.first_timestamp)
            .unwrap_or(Duration::ZERO)
    }
}

/// One IP endpoint's transmit and receive tallies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointStat {
    pub address: IpAddr,
    pub tx_frames: u64,
    pub tx_bytes: u64,
    pub rx_frames: u64,
    pub rx_bytes: u64,
}

/// One transport port's tallies, counting source and destination roles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortStat {
    pub transport: TransportKind,
    pub port: u16,
    pub frames: u64,
    pub bytes: u64,
}

/// One non-empty time bucket of the I/O series.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoBucketStat {
    pub offset: Duration,
    pub frames: u64,
    pub bytes: u64,
}

/// Everything one statistics pass computed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatsReport {
    /// I/O bucket width the series was computed with.
    pub interval: Duration,
    /// Matched frames and their captured bytes.
    pub frames: u64,
    pub bytes: u64,
    pub first_timestamp: Option<SystemTime>,
    pub last_timestamp: Option<SystemTime>,
    /// Sorted by frame count descending, then name, for stable reports.
    pub protocols: Vec<ProtocolStat>,
    /// Sorted by transport, then assigned conversation index.
    pub conversations: Vec<ConversationStat>,
    /// Sorted by address.
    pub endpoints: Vec<EndpointStat>,
    /// Sorted by transport, then port.
    pub ports: Vec<PortStat>,
    /// Non-empty buckets in time order, offset from the first matched frame.
    pub io: Vec<IoBucketStat>,
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
/// Every table is keyed by values a frame carries, so retained state grows
/// with distinct keys and never faster than the pipeline's frame budget;
/// conversations are additionally bounded by the pipeline's flow budget,
/// which fails closed before this collector would see a new index.
#[derive(Debug)]
pub struct StatsCollector {
    interval: Duration,
    frames: u64,
    bytes: u64,
    first_timestamp: Option<SystemTime>,
    last_timestamp: Option<SystemTime>,
    protocols: BTreeMap<String, Tally>,
    conversations: BTreeMap<(TransportKind, u64), ConversationState>,
    endpoints: BTreeMap<IpAddr, EndpointTally>,
    ports: BTreeMap<(TransportKind, u16), Tally>,
    io: BTreeMap<u64, Tally>,
}

impl StatsCollector {
    /// Creates a collector with the given I/O bucket width.
    pub fn new(interval: Duration) -> Result<Self, AnalysisError> {
        if interval.is_zero() {
            return Err(AnalysisError::InvalidLimit {
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
            protocols: BTreeMap::new(),
            conversations: BTreeMap::new(),
            endpoints: BTreeMap::new(),
            ports: BTreeMap::new(),
            io: BTreeMap::new(),
        })
    }

    /// Folds one matched frame into every table.
    pub fn observe(&mut self, record: &FrameRecord<'_>) {
        let bytes = u64::from(record.decoded.frame.captured_length());
        let timestamp = record.decoded.frame.timestamp;
        self.frames += 1;
        self.bytes += bytes;
        let origin = *self.first_timestamp.get_or_insert(timestamp);
        self.last_timestamp = Some(match self.last_timestamp {
            Some(last) => last.max(timestamp),
            None => timestamp,
        });

        // I/O series: a frame timestamped before the first observed frame
        // belongs to the first bucket rather than to invented negative time.
        let offset = timestamp.duration_since(origin).unwrap_or(Duration::ZERO);
        let bucket = offset.as_nanos() / self.interval.as_nanos().max(1);
        self.io
            .entry(u64::try_from(bucket).unwrap_or(u64::MAX))
            .or_default()
            .add(bytes);

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

        // IP endpoints: the innermost network layer's source transmitted
        // this frame and its destination received it.
        if let Some((source, destination)) = innermost_network(record) {
            self.endpoints.entry(source).or_default().tx.add(bytes);
            self.endpoints.entry(destination).or_default().rx.add(bytes);
        }

        // Conversations and ports, keyed by the indices the pipeline
        // assigned so filters, follow-ups, and reports all agree.
        if let (Some(stream), Some(segment)) = (record.tcp_stream, tcp_segment(record.decoded)) {
            self.conversation(TransportKind::Tcp, stream, &segment.flow, bytes, timestamp);
        }
        if let (Some(stream), Some(flow)) = (record.udp_stream, udp_flow(record.decoded)) {
            self.conversation(TransportKind::Udp, stream, &flow, bytes, timestamp);
        }
    }

    fn conversation(
        &mut self,
        transport: TransportKind,
        stream: u64,
        flow: &FlowKey,
        bytes: u64,
        timestamp: SystemTime,
    ) {
        let canonical = CanonicalFlow::from_flow(flow);
        let state = self
            .conversations
            .entry((transport, stream))
            .or_insert_with(|| ConversationState {
                flow: canonical.clone(),
                tally: DirectionalTally::default(),
                first_timestamp: timestamp,
                last_timestamp: timestamp,
            });
        if (flow.source, flow.source_port) == state.flow.first {
            state.tally.a_to_b.add(bytes);
        } else {
            state.tally.b_to_a.add(bytes);
        }
        state.first_timestamp = state.first_timestamp.min(timestamp);
        state.last_timestamp = state.last_timestamp.max(timestamp);

        // Each distinct port a frame touches counts once.
        let mut ports = [flow.source_port, flow.destination_port];
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

    /// Finishes the pass and produces every table in its stable order.
    pub fn finish(self) -> StatsReport {
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
                // Computed in wide nanoseconds so a small interval over a
                // long capture keeps exact offsets; only spans beyond what
                // Duration can hold at all saturate.
                offset: Duration::from_nanos(
                    u64::try_from(interval.as_nanos().saturating_mul(u128::from(bucket)))
                        .unwrap_or(u64::MAX),
                ),
                frames: tally.frames,
                bytes: tally.bytes,
            })
            .collect();

        StatsReport {
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
        }
    }
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
