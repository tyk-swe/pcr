// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Aggregate capture statistics computed over the analysis pipeline.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use super::session_index::{CanonicalFlow, transport_payload, transports};
use super::{AnalysisError, FlowKey, FrameRecord, Ipv4, Ipv6, Tcp};

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
        self.frames = self.frames.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
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

/// One fixed wire-length bucket, lower-inclusive and upper-exclusive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LengthBucketStat {
    pub lower_bound: u64,
    pub upper_bound: Option<u64>,
    pub frames: u64,
}

/// Distribution of original on-wire frame lengths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LengthsStat {
    pub frames: u64,
    pub minimum: Option<u64>,
    pub maximum: Option<u64>,
    pub mean: Option<u64>,
    pub buckets: Vec<LengthBucketStat>,
}

/// One fixed response-time bucket, lower-inclusive and upper-exclusive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceResponseTimeBucketStat {
    pub lower_bound: Duration,
    pub upper_bound: Option<Duration>,
    pub samples: u64,
}

/// Heuristic request-burst response-time statistics for one service port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceResponseTimeStat {
    pub transport: TransportKind,
    pub service_port: u16,
    pub request_bursts: u64,
    pub samples: u64,
    pub unanswered_requests: u64,
    pub orphan_responses: u64,
    pub timestamp_regressions: u64,
    pub minimum: Option<Duration>,
    pub maximum: Option<Duration>,
    pub mean: Option<Duration>,
    pub buckets: Vec<ServiceResponseTimeBucketStat>,
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
    pub lengths: LengthsStat,
    /// Sorted by transport, then service port.
    pub service_response_time: Vec<ServiceResponseTimeStat>,
}

const LENGTH_BUCKET_BOUNDS: [u128; 15] = [
    0, 64, 128, 256, 512, 1024, 1519, 2048, 4096, 8192, 16_384, 32_768, 65_536, 131_072, 262_144,
];

const RESPONSE_TIME_BUCKET_BOUNDS: [u128; 8] = [
    0,
    1_000_000,
    10_000_000,
    100_000_000,
    1_000_000_000,
    2_000_000_000,
    5_000_000_000,
    10_000_000_000,
];

#[derive(Clone, Debug)]
struct FixedHistogram<const N: usize> {
    bounds: [u128; N],
    counts: [u64; N],
    count: u64,
    sum: u128,
    minimum: Option<u128>,
    maximum: Option<u128>,
}

impl<const N: usize> FixedHistogram<N> {
    fn new(bounds: [u128; N]) -> Self {
        Self {
            bounds,
            counts: [0; N],
            count: 0,
            sum: 0,
            minimum: None,
            maximum: None,
        }
    }

    fn add(&mut self, value: u128) {
        let index = self.bounds[1..].partition_point(|bound| value >= *bound);
        self.counts[index] = self.counts[index].saturating_add(1);
        self.count = self.count.saturating_add(1);
        self.sum = self.sum.saturating_add(value);
        self.minimum = Some(self.minimum.map_or(value, |old| old.min(value)));
        self.maximum = Some(self.maximum.map_or(value, |old| old.max(value)));
    }

    fn mean(&self) -> Option<u128> {
        (self.count != 0).then(|| self.sum / u128::from(self.count))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ServiceEndpoint {
    address: IpAddr,
    port: u16,
}

#[derive(Clone, Debug, Default)]
struct PairingState {
    requester: Option<ServiceEndpoint>,
    service: Option<ServiceEndpoint>,
    pending: Option<SystemTime>,
    response_active: bool,
    syn_sequence: Option<u32>,
}

#[derive(Clone, Debug, Default)]
struct ServiceRowState {
    request_bursts: u64,
    unanswered_requests: u64,
    orphan_responses: u64,
    timestamp_regressions: u64,
    histogram: FixedHistogram<8>,
}

impl Default for FixedHistogram<8> {
    fn default() -> Self {
        Self::new(RESPONSE_TIME_BUCKET_BOUNDS)
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
    io_origin: Option<SystemTime>,
    protocols: BTreeMap<String, Tally>,
    conversations: BTreeMap<(TransportKind, u64), ConversationState>,
    endpoints: BTreeMap<IpAddr, EndpointTally>,
    ports: BTreeMap<(TransportKind, u16), Tally>,
    io: BTreeMap<u64, Tally>,
    lengths: FixedHistogram<15>,
    service_conversations: BTreeMap<(TransportKind, u64), PairingState>,
    service_rows: BTreeMap<(TransportKind, u16), ServiceRowState>,
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
            io_origin: None,
            protocols: BTreeMap::new(),
            conversations: BTreeMap::new(),
            endpoints: BTreeMap::new(),
            ports: BTreeMap::new(),
            io: BTreeMap::new(),
            lengths: FixedHistogram::new(LENGTH_BUCKET_BOUNDS),
            service_conversations: BTreeMap::new(),
            service_rows: BTreeMap::new(),
        })
    }

    /// Folds one matched frame into every table.
    pub fn observe(&mut self, record: &FrameRecord<'_>) {
        let bytes = u64::from(record.decoded.frame.captured_length());
        let original_length = u128::from(record.decoded.frame.original_length());
        let timestamp = record.decoded.frame.timestamp;
        self.frames = self.frames.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
        self.lengths.add(original_length);
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

        // IP endpoints: the innermost network layer's source transmitted
        // this frame and its destination received it.
        if let Some((source, destination)) = innermost_network(record) {
            self.endpoints.entry(source).or_default().tx.add(bytes);
            self.endpoints.entry(destination).or_default().rx.add(bytes);
        }

        // Conversations and ports, keyed by the indices the pipeline
        // assigned so filters, follow-ups, and reports all agree.
        let frame_transports = transports(&record.decoded.packet);
        if let (Some(stream), Some((index, flow, tcp))) = (record.tcp_stream, frame_transports.tcp)
        {
            let payload = transport_payload(record.decoded, index);
            self.conversation(TransportKind::Tcp, stream, &flow, bytes, timestamp);
            self.observe_tcp_service(stream, &flow, tcp.sequence, tcp.flags, &payload, timestamp);
        }
        if let (Some(stream), Some((_, flow))) = (record.udp_stream, frame_transports.udp) {
            self.conversation(TransportKind::Udp, stream, &flow, bytes, timestamp);
            self.observe_udp_service(stream, &flow, timestamp);
        }
    }

    fn observe_tcp_service(
        &mut self,
        stream: u64,
        flow: &FlowKey,
        sequence: u32,
        flags: u16,
        payload: &[u8],
        timestamp: SystemTime,
    ) {
        let source = ServiceEndpoint {
            address: flow.source,
            port: flow.source_port,
        };
        let destination = ServiceEndpoint {
            address: flow.destination,
            port: flow.destination_port,
        };
        let syn = flags & Tcp::SYN != 0;
        let ack = flags & Tcp::ACK != 0;
        let mut abandoned_port = None;
        let service = {
            let state = self
                .service_conversations
                .entry((TransportKind::Tcp, stream))
                .or_default();
            if syn && !ack {
                if state.syn_sequence != Some(sequence) {
                    if state.pending.take().is_some() {
                        abandoned_port = state.service.map(|endpoint| endpoint.port);
                    }
                    state.response_active = false;
                    state.requester = Some(source);
                    state.service = Some(destination);
                    state.syn_sequence = Some(sequence);
                }
            } else if state.requester.is_none() {
                if syn && ack {
                    state.requester = Some(destination);
                    state.service = Some(source);
                } else {
                    state.requester = Some(source);
                    state.service = Some(destination);
                }
            }
            state.service
        };

        if let Some(port) = abandoned_port {
            let row = self
                .service_rows
                .entry((TransportKind::Tcp, port))
                .or_default();
            row.unanswered_requests = row.unanswered_requests.saturating_add(1);
        }
        let Some(service) = service else { return };
        self.service_rows
            .entry((TransportKind::Tcp, service.port))
            .or_default();
        if !payload.is_empty() {
            self.observe_pairing((TransportKind::Tcp, stream), source, timestamp);
        }
    }

    fn observe_udp_service(&mut self, stream: u64, flow: &FlowKey, timestamp: SystemTime) {
        let source = ServiceEndpoint {
            address: flow.source,
            port: flow.source_port,
        };
        let destination = ServiceEndpoint {
            address: flow.destination,
            port: flow.destination_port,
        };
        let service = {
            let state = self
                .service_conversations
                .entry((TransportKind::Udp, stream))
                .or_default();
            if state.requester.is_none() {
                state.requester = Some(source);
                state.service = Some(destination);
            }
            state.service
        };
        if let Some(service) = service {
            self.service_rows
                .entry((TransportKind::Udp, service.port))
                .or_default();
            self.observe_pairing((TransportKind::Udp, stream), source, timestamp);
        }
    }

    fn observe_pairing(
        &mut self,
        key: (TransportKind, u64),
        source: ServiceEndpoint,
        timestamp: SystemTime,
    ) {
        enum Outcome {
            Burst,
            Response(u128),
            Regression,
            Orphan,
        }

        let (port, outcome) = {
            let state = self.service_conversations.get_mut(&key).unwrap();
            let Some(requester) = state.requester else {
                return;
            };
            let Some(service) = state.service else { return };
            let outcome = if source == requester {
                state.response_active = false;
                if state.pending.replace(timestamp).is_some() {
                    return;
                }
                Outcome::Burst
            } else if source == service {
                if state.response_active {
                    return;
                }
                state.response_active = true;
                match state.pending.take() {
                    Some(pending) => match timestamp.duration_since(pending) {
                        Ok(duration) => Outcome::Response(duration.as_nanos()),
                        Err(_) => Outcome::Regression,
                    },
                    None => Outcome::Orphan,
                }
            } else {
                Outcome::Orphan
            };
            (service.port, outcome)
        };

        let row = self.service_rows.entry((key.0, port)).or_default();
        match outcome {
            Outcome::Burst => {
                row.request_bursts = row.request_bursts.saturating_add(1);
            }
            Outcome::Response(nanoseconds) => row.histogram.add(nanoseconds),
            Outcome::Regression => {
                row.timestamp_regressions = row.timestamp_regressions.saturating_add(1);
            }
            Outcome::Orphan => {
                row.orphan_responses = row.orphan_responses.saturating_add(1);
            }
        }
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

        // I/O series: a frame timestamped before the first observed frame
        // belongs to the first bucket rather than to invented negative time.
        let offset = timestamp.duration_since(origin).unwrap_or(Duration::ZERO);
        let bucket = offset.as_nanos() / self.interval.as_nanos().max(1);
        self.io
            .entry(u64::try_from(bucket).unwrap_or(u64::MAX))
            .or_default()
            .add(bytes);
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
                offset: duration_from_nanos_saturating(
                    interval.as_nanos().saturating_mul(u128::from(bucket)),
                ),
                frames: tally.frames,
                bytes: tally.bytes,
            })
            .collect();

        let lengths = lengths_stat(self.lengths);
        let mut service_rows = self.service_rows;
        for ((transport, _stream), state) in self.service_conversations {
            if let (Some(service), Some(_)) = (state.service, state.pending) {
                let row = service_rows.entry((transport, service.port)).or_default();
                row.unanswered_requests = row.unanswered_requests.saturating_add(1);
            }
        }
        let service_response_time = service_rows
            .into_iter()
            .map(|((transport, service_port), state)| {
                service_response_stat(transport, service_port, state)
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
            lengths,
            service_response_time,
        }
    }
}

fn lengths_stat(histogram: FixedHistogram<15>) -> LengthsStat {
    let buckets = histogram
        .bounds
        .iter()
        .enumerate()
        .filter(|(index, _)| histogram.counts[*index] != 0)
        .map(|(index, bound)| LengthBucketStat {
            lower_bound: u64::try_from(*bound).expect("fixed length bound fits u64"),
            upper_bound: histogram
                .bounds
                .get(index + 1)
                .map(|upper| u64::try_from(*upper).expect("fixed length bound fits u64")),
            frames: histogram.counts[index],
        })
        .collect();
    LengthsStat {
        frames: histogram.count,
        minimum: histogram
            .minimum
            .map(|value| u64::try_from(value).expect("frame length fits u64")),
        maximum: histogram
            .maximum
            .map(|value| u64::try_from(value).expect("frame length fits u64")),
        mean: histogram
            .mean()
            .map(|value| u64::try_from(value).expect("frame length fits u64")),
        buckets,
    }
}

fn service_response_stat(
    transport: TransportKind,
    service_port: u16,
    state: ServiceRowState,
) -> ServiceResponseTimeStat {
    let buckets = state
        .histogram
        .bounds
        .iter()
        .enumerate()
        .filter(|(index, _)| state.histogram.counts[*index] != 0)
        .map(|(index, bound)| ServiceResponseTimeBucketStat {
            lower_bound: duration_from_nanos_saturating(*bound),
            upper_bound: state
                .histogram
                .bounds
                .get(index + 1)
                .map(|upper| duration_from_nanos_saturating(*upper)),
            samples: state.histogram.counts[index],
        })
        .collect();
    ServiceResponseTimeStat {
        transport,
        service_port,
        request_bursts: state.request_bursts,
        samples: state.histogram.count,
        unanswered_requests: state.unanswered_requests,
        orphan_responses: state.orphan_responses,
        timestamp_regressions: state.timestamp_regressions,
        minimum: state.histogram.minimum.map(duration_from_nanos_saturating),
        maximum: state.histogram.maximum.map(duration_from_nanos_saturating),
        mean: state.histogram.mean().map(duration_from_nanos_saturating),
        buckets,
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

#[cfg(test)]
mod tests {
    use super::{FixedHistogram, StatsCollector, duration_from_nanos_saturating};
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn wide_nanosecond_offsets_use_durations_full_range() {
        let six_hundred_years = 600_u128 * 365 * 24 * 60 * 60 * 1_000_000_000;
        assert!(duration_from_nanos_saturating(six_hundred_years) > Duration::from_nanos(u64::MAX));
        assert_eq!(duration_from_nanos_saturating(u128::MAX), Duration::MAX);
    }

    #[test]
    fn out_of_order_timestamps_do_not_move_the_io_origin() {
        let mut collector = StatsCollector::new(Duration::from_secs(1)).unwrap();
        collector.observe_time(UNIX_EPOCH + Duration::from_secs(10), 1);
        collector.observe_time(UNIX_EPOCH + Duration::from_secs(5), 1);
        collector.observe_time(UNIX_EPOCH + Duration::from_secs(11), 1);
        let report = collector.finish();

        assert_eq!(
            report.first_timestamp,
            Some(UNIX_EPOCH + Duration::from_secs(5))
        );
        assert_eq!(report.io[0].frames, 2);
        assert_eq!(report.io[1].offset, Duration::from_secs(1));
    }

    #[test]
    fn fixed_histogram_uses_lower_inclusive_upper_exclusive_buckets() {
        let mut histogram = FixedHistogram::new([0, 10, 20]);
        for value in [0, 9, 10, 19, 20] {
            histogram.add(value);
        }
        assert_eq!(histogram.counts, [2, 2, 1]);
        assert_eq!(histogram.count, 5);
        assert_eq!(histogram.minimum, Some(0));
        assert_eq!(histogram.maximum, Some(20));
        assert_eq!(histogram.mean(), Some(11));
    }

    #[test]
    fn fixed_histogram_empty_and_extreme_values_finish_without_overflow() {
        let empty = FixedHistogram::new([0, 1]);
        assert_eq!(empty.count, 0);
        assert_eq!(empty.mean(), None);
        assert_eq!(empty.minimum, None);
        assert_eq!(empty.maximum, None);
        let mut histogram = FixedHistogram::new([0]);
        histogram.add(u128::MAX);
        histogram.add(u128::MAX);
        assert_eq!(histogram.count, 2);
        assert_eq!(histogram.sum, u128::MAX);
        assert_eq!(histogram.counts, [2]);
    }
}
