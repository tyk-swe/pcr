// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::protocol::network::{Ipv4, Ipv6};

use crate::analysis::StreamTransport;
use crate::analysis::conversation_index::CanonicalFlow;
use crate::analysis::pipeline::{FrameRecord, Summary as RunSummary};
use crate::analysis::reassembly::tcp::ScopedFlowKey;
use crate::analysis::{Constraint, Error};

mod report;
mod timing;
pub use report::{
    ConversationStat, EndpointStat, IoBucketStat, PortStat, ProtocolStat, Report, SizeBinStat,
};
pub use timing::{AckRttStat, TcpTimingStat};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Table {
    #[default]
    All,
    Protocols,
    Conversations,
    Endpoints,
    Ports,
    Io,
    Fragments,
    Sizes,
    TcpTiming,
}

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
    scope: crate::analysis::scope::Definition,
    tally: DirectionalTally,
    first_timestamp: SystemTime,
    last_timestamp: SystemTime,
}

#[derive(Clone, Copy, Debug, Default)]
struct EndpointTally {
    tx: Tally,
    rx: Tally,
}

#[derive(Debug)]
pub struct Collector {
    table: Table,
    interval: Duration,
    frames: u64,
    bytes: u64,
    first_timestamp: Option<SystemTime>,
    last_timestamp: Option<SystemTime>,
    io_origin: Option<SystemTime>,
    io_underflow_frames: u64,
    protocols: BTreeMap<String, Tally>,
    conversations: BTreeMap<(StreamTransport, u64), ConversationState>,
    endpoints: BTreeMap<IpAddr, EndpointTally>,
    ports: BTreeMap<(StreamTransport, u16), Tally>,
    io: BTreeMap<u64, Tally>,
    sizes: [Tally; 8],
    tcp_timing: BTreeMap<u64, timing::State>,
}

impl Collector {
    pub fn new(interval: Duration) -> Result<Self, Error> {
        Self::for_table(interval, Table::All)
    }

    pub fn for_table(interval: Duration, table: Table) -> Result<Self, Error> {
        if interval.is_zero() {
            return Err(Error::InvalidLimit {
                field: "interval",
                value: 0,
                reason: Constraint::NonZero,
            });
        }
        Ok(Self {
            table,
            interval,
            frames: 0,
            bytes: 0,
            first_timestamp: None,
            last_timestamp: None,
            io_origin: None,
            io_underflow_frames: 0,
            protocols: BTreeMap::new(),
            conversations: BTreeMap::new(),
            endpoints: BTreeMap::new(),
            ports: BTreeMap::new(),
            io: BTreeMap::new(),
            sizes: [Tally::default(); 8],
            tcp_timing: BTreeMap::new(),
        })
    }

    pub fn observe(&mut self, record: &FrameRecord<'_>) {
        let bytes = u64::from(record.decoded.frame.captured_length());
        let timestamp = record.timestamp;
        self.frames = self.frames.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
        self.observe_time(timestamp, bytes);
        if self.collects(Table::Sizes) {
            let bin = match bytes {
                0..=63 => 0,
                64..=127 => 1,
                128..=255 => 2,
                256..=511 => 3,
                512..=1023 => 4,
                1024..=1518 => 5,
                1519..=4095 => 6,
                _ => 7,
            };
            self.sizes[bin].add(bytes);
        }
        if self.collects(Table::TcpTiming)
            && let Some(view) = record.tcp
            && let Some(conversation) = view.conversation
        {
            self.tcp_timing
                .entry(conversation.index)
                .or_insert_with(|| timing::State::new(conversation.index, conversation.flow))
                .observe(
                    conversation.flow,
                    view.header,
                    view.payload.len(),
                    timestamp,
                    record.clock_regression.is_some(),
                );
        }

        if self.collects(Table::Protocols) {
            let mut seen: Vec<&str> = Vec::new();
            for layer in record.decoded.packet.iter() {
                let name = layer.protocol_id().as_str();
                if !seen.contains(&name) {
                    seen.push(name);
                }
            }
            for name in seen {
                if let Some(tally) = self.protocols.get_mut(name) {
                    tally.add(bytes);
                } else {
                    let mut tally = Tally::default();
                    tally.add(bytes);
                    self.protocols.insert(name.to_owned(), tally);
                }
            }
        }

        if self.collects(Table::Endpoints)
            && let Some((source, destination)) = innermost_network(record)
        {
            self.endpoints.entry(source).or_default().tx.add(bytes);
            self.endpoints.entry(destination).or_default().rx.add(bytes);
        }

        for (transport, conversation) in [
            (
                StreamTransport::Tcp,
                record.tcp.and_then(|view| view.conversation),
            ),
            (
                StreamTransport::Udp,
                record.udp.and_then(|view| view.conversation),
            ),
        ] {
            if let Some(stream) = conversation {
                if self.collects(Table::Conversations) {
                    self.record_conversation(
                        transport,
                        stream.index,
                        stream.flow,
                        bytes,
                        timestamp,
                        record,
                    );
                }
                if self.collects(Table::Ports) {
                    self.record_ports(transport, stream.flow, bytes);
                }
            }
        }
    }

    fn collects(&self, table: Table) -> bool {
        self.table == Table::All || self.table == table
    }

    fn observe_time(&mut self, timestamp: SystemTime, bytes: u64) {
        self.first_timestamp = Some(
            self.first_timestamp
                .map_or(timestamp, |first| first.min(timestamp)),
        );
        self.last_timestamp = Some(
            self.last_timestamp
                .map_or(timestamp, |last| last.max(timestamp)),
        );

        if !self.collects(Table::Io) {
            return;
        }
        let origin = *self.io_origin.get_or_insert(timestamp);
        if timestamp < origin {
            self.io_underflow_frames = self.io_underflow_frames.saturating_add(1);
        }
        let offset = timestamp.duration_since(origin).unwrap_or(Duration::ZERO);
        let bucket = offset.as_nanos() / self.interval.as_nanos().max(1);
        self.io
            .entry(u64::try_from(bucket).unwrap_or(u64::MAX))
            .or_default()
            .add(bytes);
    }

    fn record_conversation(
        &mut self,
        transport: StreamTransport,
        stream: u64,
        flow: &ScopedFlowKey,
        bytes: u64,
        timestamp: SystemTime,
        record: &FrameRecord<'_>,
    ) {
        let canonical = CanonicalFlow::from_flow(flow);
        let state = self
            .conversations
            .entry((transport, stream))
            .or_insert_with(|| ConversationState {
                flow: canonical,
                scope: record
                    .scope_definition(flow.scope)
                    .expect("indexed scope exists")
                    .clone(),
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
    }

    fn record_ports(&mut self, transport: StreamTransport, flow: &ScopedFlowKey, bytes: u64) {
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

    pub fn finish(self, summary: &RunSummary) -> Report {
        let ip_reassembly = summary.ip_reassembly.clone();
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
                scope: state.scope,
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
            clock: summary.clock.clone(),
            io_origin: self.io_origin,
            io_underflow_frames: self.io_underflow_frames,
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
            interfaces: summary.interfaces.clone(),
            sizes: if self.table == Table::All || self.table == Table::Sizes {
                self.sizes
                    .into_iter()
                    .enumerate()
                    .map(|(index, tally)| {
                        const LOW: [u32; 8] = [0, 64, 128, 256, 512, 1024, 1519, 4096];
                        const HIGH: [Option<u32>; 8] = [
                            Some(63),
                            Some(127),
                            Some(255),
                            Some(511),
                            Some(1023),
                            Some(1518),
                            Some(4095),
                            None,
                        ];
                        report::SizeBinStat {
                            minimum: LOW[index],
                            maximum: HIGH[index],
                            frames: tally.frames,
                            bytes: tally.bytes,
                        }
                    })
                    .collect()
            } else {
                Vec::new()
            },
            tcp_timing: self
                .tcp_timing
                .into_values()
                .map(timing::State::finish)
                .collect(),
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

fn innermost_network(record: &FrameRecord<'_>) -> Option<(IpAddr, IpAddr)> {
    let mut network = None;
    for layer in record.decoded.packet.iter() {
        if let Some(ipv4) = layer.downcast_ref::<Ipv4>() {
            network = Some((ipv4.source.into(), ipv4.destination.into()));
        } else if let Some(ipv6) = layer.downcast_ref::<Ipv6>() {
            network = Some((ipv6.source.into(), ipv6.destination.into()));
        }
    }
    network
}
