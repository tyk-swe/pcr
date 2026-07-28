// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The bounded read → dissect → index → filter → dispatch loop shared by the
//! offline analysis commands.

use std::collections::HashSet;
use std::time::{Duration, Instant, SystemTime};

use super::session_index::{StreamIndex, ip_fragment, tcp_segment, transports, udp_flow};
use super::{
    AnalysisError, Arc, Bytes, CaptureError, DEFAULT_SIZE_LIMIT, DEFAULT_STREAM_BYTES,
    DEFAULT_STREAM_FRAMES, Deadline, DecodeOptions, DecodedPacket, Decoder, Filter, FilterContext,
    FlowKey, FragmentEvent, FragmentReassembler, OverlapPolicy, ProtocolRegistry, Read, Reader,
    ReassemblyLimits, Segment, SessionTcpError, Tcp, TcpEvent, TcpReassembler,
};

const DEFAULT_MAX_ANALYSIS_FLOWS: usize = 8_192;

/// Finite resource ceilings for one analysis run.
///
/// The frame and byte budgets count every frame the capture yields, matched
/// or not, so a display filter can never raise how much input one run reads.
/// The duration budget bounds the run's own processing time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnalysisLimits {
    pub max_frames: u64,
    pub max_bytes: u64,
    pub max_frame_bytes: usize,
    pub max_flows: usize,
    pub max_duration: Duration,
}

impl Default for AnalysisLimits {
    fn default() -> Self {
        Self {
            max_frames: DEFAULT_STREAM_FRAMES,
            max_bytes: DEFAULT_STREAM_BYTES,
            max_frame_bytes: DEFAULT_SIZE_LIMIT,
            max_flows: DEFAULT_MAX_ANALYSIS_FLOWS,
            max_duration: Duration::from_secs(3_600),
        }
    }
}

impl AnalysisLimits {
    pub fn validate(&self) -> Result<(), AnalysisError> {
        for (field, value) in [
            ("max_frames", self.max_frames),
            ("max_bytes", self.max_bytes),
            ("max_frame_bytes", self.max_frame_bytes as u64),
            ("max_flows", self.max_flows as u64),
        ] {
            if value == 0 {
                return Err(AnalysisError::InvalidLimit {
                    field,
                    value,
                    reason: "must be non-zero",
                });
            }
        }
        if self.max_frame_bytes as u64 > self.max_bytes {
            return Err(AnalysisError::InvalidLimit {
                field: "max_frame_bytes",
                value: self.max_frame_bytes as u64,
                reason: "cannot exceed max_bytes",
            });
        }
        if self.max_duration.is_zero() {
            return Err(AnalysisError::InvalidLimit {
                field: "max_duration",
                value: 0,
                reason: "must be non-zero",
            });
        }
        Ok(())
    }
}

/// What one analysis run computes beyond dispatching matched frames.
#[derive(Clone, Debug, Default)]
pub struct AnalysisOptions<'a> {
    /// Keeps only matching frames; compiled by the caller so filter mistakes
    /// surface before any input is read. Conversation indices are assigned
    /// before the filter runs, so `tcp.stream` and `udp.stream` resolve.
    pub filter: Option<&'a Filter>,
    /// Drives bounded TCP reassembly over the matched frames and delivers
    /// its events with each record. Costs memory proportional to reordering,
    /// so commands that only count leave it off.
    pub tcp_events: bool,
    pub limits: AnalysisLimits,
}

/// One matched frame, dispatched in capture order.
#[derive(Debug)]
pub struct FrameRecord<'a> {
    /// 1-based position in the capture, counting unmatched frames too, so
    /// numbers agree with every other command reading the same file.
    pub number: u64,
    pub decoded: &'a DecodedPacket,
    /// Conversation index of the innermost TCP flow, when there is one.
    pub tcp_stream: Option<u64>,
    /// Conversation index of the innermost UDP flow, when there is one.
    pub udp_stream: Option<u64>,
    /// TCP reassembly events this frame produced, when requested, including
    /// evictions of flows whose idle expiry this frame's arrival revealed.
    pub tcp_events: &'a [TcpEvent],
    /// Fragment reassembly outcomes: a datagram this frame completed, and
    /// any datagrams whose expiry this frame's arrival revealed.
    pub fragment_events: &'a [FragmentEvent],
}

/// Terminal counters and residue for a completed analysis run.
#[derive(Clone, Debug)]
pub struct AnalysisSummary {
    pub frames_read: u64,
    pub frames_matched: u64,
    pub bytes_read: u64,
    pub tcp_stream_count: u64,
    pub udp_stream_count: u64,
    /// Data still buffered when the capture ended, flushed flow by flow.
    /// Streams that never saw FIN or RST surface their bytes here.
    pub trailing_tcp_events: Vec<TcpEvent>,
    /// Fragmented datagrams still incomplete when the capture ended, so
    /// missing tail fragments are reportable rather than silently dropped.
    pub trailing_fragment_events: Vec<FragmentEvent>,
}

/// Runs the shared analysis loop, dispatching each matched frame to `sink`.
///
/// The reader arrives configured with its own per-frame and interface
/// bounds; this loop enforces the aggregate frame, byte, flow, and duration
/// budgets, dissects under `limits.max_frame_bytes`, assigns conversation
/// indices to every frame, applies the filter, and drives reassembly for the
/// frames the filter keeps.
///
/// Reassembly follows capture time, not wall-clock time: idle expiry is
/// measured between frame timestamps, so analyzing an old capture behaves
/// the same today as it did the day it was recorded.
pub fn run<R, F>(
    reader: &mut Reader<R>,
    registry: Arc<ProtocolRegistry>,
    options: &AnalysisOptions<'_>,
    mut sink: F,
) -> Result<AnalysisSummary, AnalysisError>
where
    R: Read,
    F: FnMut(FrameRecord<'_>) -> Result<(), crate::BoundaryError>,
{
    options.limits.validate()?;
    let limits = &options.limits;
    let deadline = Deadline::new(limits.max_duration);
    let decoder = Decoder::new(registry);
    let mut tcp_streams = StreamIndex::new();
    let mut udp_streams = StreamIndex::new();
    // The flow budget governs reassembly state too: fragmented datagrams
    // never reach a stream index, so without this a fragment-heavy capture
    // could buffer the session default regardless of the configured bound.
    // The budget counts direction-neutral conversations, and the TCP
    // reassembler keys each direction separately, so it gets two flow slots
    // per conversation.
    let mut tcp_reassembler = options.tcp_events.then(|| {
        TcpReassembler::new(ReassemblyLimits {
            max_flows: limits.max_flows.saturating_mul(2),
            ..ReassemblyLimits::default()
        })
    });
    // Directional flows whose latest pushed segment was a bare opening SYN.
    // The reassembler cannot tell a pure SYN from a SYN-ACK — its segments
    // carry no acknowledgment — and only a peer's own bare opening SYN may
    // survive a new pure SYN on the same tuple, as in a simultaneous open.
    let mut half_open_pure_syns: HashSet<FlowKey> = HashSet::new();
    let mut fragments = FragmentReassembler::new(
        ReassemblyLimits {
            max_flows: limits.max_flows,
            ..ReassemblyLimits::default()
        },
        OverlapPolicy::default(),
    );
    let mut clock = CaptureClock::new();

    let mut frames_read = 0_u64;
    let mut frames_matched = 0_u64;
    let mut bytes_read = 0_u64;
    loop {
        enforce_deadline(&deadline, limits)?;
        let number = frames_read.checked_add(1).ok_or(AnalysisError::Capture {
            number: frames_read,
            source: CaptureError::FrameLimitExceeded {
                actual: u64::MAX,
                limit: limits.max_frames,
            },
        })?;
        let Some(frame) = reader
            .next_frame()
            .map_err(|source| AnalysisError::Capture { number, source })?
        else {
            break;
        };
        frames_read = number;
        if frames_read > limits.max_frames {
            return Err(AnalysisError::Capture {
                number,
                source: CaptureError::FrameLimitExceeded {
                    actual: frames_read,
                    limit: limits.max_frames,
                },
            });
        }
        bytes_read = bytes_read
            .checked_add(u64::from(frame.captured_length()))
            .filter(|bytes| *bytes <= limits.max_bytes)
            .ok_or(AnalysisError::Capture {
                number,
                source: CaptureError::StreamByteLimitExceeded {
                    actual: bytes_read.saturating_add(u64::from(frame.captured_length())),
                    limit: limits.max_bytes,
                },
            })?;

        let timestamp = frame.timestamp;
        let decoded = decoder
            .decode(
                frame,
                DecodeOptions {
                    max_packet_size: limits.max_frame_bytes,
                    ..DecodeOptions::default()
                },
            )
            .map_err(|source| AnalysisError::Decode { number, source })?;

        // Conversation indices exist independently of the filter, so an
        // index reported by an unfiltered run names the same conversation in
        // a filtered one.
        let segment = tcp_segment(&decoded);
        let tcp_stream = match &segment {
            Some(segment) => Some(tcp_streams.assign(&segment.flow, number, limits.max_flows)?),
            None => None,
        };
        let udp_stream = match udp_flow(&decoded) {
            Some(flow) => Some(udp_streams.assign(&flow, number, limits.max_flows)?),
            None => None,
        };

        if let Some(filter) = options.filter
            && !filter.matches(&FilterContext {
                decoded: &decoded,
                number,
                tcp_stream,
                udp_stream,
            })
        {
            continue;
        }
        frames_matched += 1;

        // Reassembly consumes only matched frames, so a filtered run buffers
        // only the conversations the operator asked about. Idle state expires
        // by capture time: exactly before every push, so a frame arriving
        // after a flow's idle window can never merge into stale state, and on
        // a throttled cadence otherwise, so idle state is still released
        // while nothing is being pushed. The eviction evidence rides with the
        // frame whose arrival revealed it.
        let now = clock.at(timestamp);
        let sweep_due = clock.should_sweep(now);
        let mut tcp_events = Vec::new();
        let mut fragment_events = Vec::new();
        if let Some(reassembler) = &mut tcp_reassembler {
            // A segment with no payload and no state-changing flag — the
            // common bare acknowledgment — advances reassembly by nothing,
            // so it is not allowed to consume flow state; it still received
            // its conversation index above.
            let pushable = segment.as_ref().is_some_and(|segment| {
                !segment.payload.is_empty() || segment.syn || segment.fin || segment.rst
            });
            if pushable || sweep_due {
                tcp_events.extend(reassembler.expire(now));
            }
            if pushable && let Some(segment) = segment {
                let acknowledged = transports(&decoded.packet)
                    .tcp
                    .is_some_and(|(_, _, tcp)| tcp.flags & Tcp::ACK != 0);
                if segment.syn && !acknowledged && segment.payload.is_empty() {
                    // Bounded like the flow table itself; past the cap a
                    // flow simply loses simultaneous-open protection.
                    if half_open_pure_syns.len() < limits.max_flows.saturating_mul(2) {
                        half_open_pure_syns.insert(segment.flow.clone());
                    }
                } else {
                    half_open_pure_syns.remove(&segment.flow);
                }
                // A SYN — client SYN or SYN-ACK — that replaces this
                // direction's tracked generation reuses the four-tuple for a
                // new connection, so whatever the reverse direction retained
                // belongs to the finished one; interpreting the next reverse
                // segment against that stale base would fabricate evidence.
                // A retransmitted handshake SYN renews the same base and
                // evicts nothing. When this direction has no tracked state
                // at all, the reverse is judged on its own terms: a SYN-ACK
                // vouches only for the opening SYN it acknowledges, and a
                // pure SYN can coexist only with a payload-free reverse —
                // this same handshake's opening SYN, as in a simultaneous
                // open.
                if segment.syn {
                    let first = segment.sequence.wrapping_add(1);
                    let acknowledgment = acknowledged
                        .then(|| {
                            transports(&decoded.packet)
                                .tcp
                                .map(|(_, _, tcp)| tcp.acknowledgment)
                        })
                        .flatten();
                    let reverse = segment.flow.reverse();
                    // A SYN-ACK acknowledging something outside the tracked
                    // reverse range names a SYN this capture did not see:
                    // the tracked state is a previous connection's, even
                    // when the sender reuses its old sequence base. The
                    // range runs from the reverse base to its delivered
                    // cursor, since a Fast Open SYN's payload is
                    // acknowledged along with the SYN itself. The verdict is
                    // three-way — confirmed, contradicted, or nothing
                    // tracked that can say either way.
                    let reverse_verdict = acknowledgment.and_then(|acknowledgment| {
                        match (
                            reassembler.flow_base_sequence(&reverse),
                            reassembler.flow_next_sequence(&reverse),
                        ) {
                            (Some(base), Some(next)) => Some(
                                acknowledgment.wrapping_sub(base) < 0x8000_0000
                                    && next.wrapping_sub(acknowledgment) < 0x8000_0000,
                            ),
                            _ => None,
                        }
                    });
                    let acknowledgment_disagrees = reverse_verdict == Some(false);
                    let own_base = reassembler.flow_base_sequence(&segment.flow);
                    // A handshake SYN only retransmits while the connection
                    // is half-open, so a payload-free pure SYN arriving
                    // after this direction already carried payload or a FIN
                    // is a new connection even when it lands on the same
                    // base. A SYN carrying payload is a Fast Open open or
                    // its retransmission, which the same-base rule keeps.
                    let reuse = match own_base {
                        Some(base) => {
                            base != first
                                || acknowledgment_disagrees
                                || (acknowledgment.is_none()
                                    && segment.payload.is_empty()
                                    && reassembler.flow_observed_payload(&segment.flow))
                        }
                        None => {
                            if acknowledgment.is_some() {
                                acknowledgment_disagrees
                            } else {
                                // Only the peer's own bare opening SYN may
                                // coexist with this pure SYN; a SYN-ACK's or
                                // an established generation's state belongs
                                // to a connection this handshake is not.
                                !half_open_pure_syns.contains(&reverse)
                            }
                        }
                    };
                    if reuse {
                        // A reverse the acknowledgment positively confirms
                        // is the new connection's own opening SYN — only
                        // this direction's stale generation is replaced.
                        if reverse_verdict != Some(true) {
                            tcp_events.extend(reassembler.evict_flow(&reverse));
                        }
                        // The push below would replace this direction's
                        // tracked generation silently, discarding whatever
                        // it still buffered; evicting explicitly surfaces
                        // those pending bytes as evidence instead.
                        if own_base.is_some() {
                            tcp_events.extend(reassembler.evict_flow(&segment.flow));
                        }
                    }
                }
                // A reset ends the conversation in both directions, and what
                // either side still buffered belongs to the connection the
                // reset killed. Both flows are evicted explicitly so those
                // pending bytes surface as evidence — the push below would
                // retire the sender's flow silently.
                // A reset's payload is explanatory diagnostic text, not
                // stream data, so it is never offered for reassembly.
                let segment = if segment.rst {
                    tcp_events.extend(reassembler.evict_flow(&segment.flow.reverse()));
                    tcp_events.extend(reassembler.evict_flow(&segment.flow));
                    Segment {
                        payload: Bytes::new(),
                        ..segment
                    }
                } else {
                    segment
                };
                match reassembler.push(segment.clone(), now) {
                    Ok(events) => tcp_events.extend(events),
                    // A segment the flow's bounded window cannot absorb — a
                    // sparse or filtered capture routinely jumps further
                    // than the reassembly window — must not end the
                    // analysis. The flow is evicted, surfacing whatever it
                    // still buffered, and the segment re-anchors a fresh
                    // generation; the header-level gap evidence survives in
                    // the collector's own cursors. A second failure is a
                    // real resource limit and still fails closed, as do
                    // malformed sequences that conflict with a delivered
                    // FIN.
                    Err(
                        SessionTcpError::FlowByteLimit { .. }
                        | SessionTcpError::SegmentLimit { .. }
                        | SessionTcpError::AggregateByteLimit { .. },
                    ) => {
                        tcp_events.extend(reassembler.evict_flow(&segment.flow));
                        tcp_events.extend(
                            reassembler
                                .push(segment, now)
                                .map_err(|source| AnalysisError::Reassembly { number, source })?,
                        );
                    }
                    Err(source) => {
                        return Err(AnalysisError::Reassembly { number, source });
                    }
                }
            }
        }
        let fragment = ip_fragment(&decoded);
        if fragment.is_some() || sweep_due {
            fragment_events.extend(fragments.expire(now));
        }
        if let Some(fragment) = fragment {
            fragment_events.extend(
                fragments
                    .push(fragment, now)
                    .map_err(|source| AnalysisError::Fragments { number, source })?,
            );
        }

        enforce_deadline(&deadline, limits)?;
        sink(FrameRecord {
            number,
            decoded: &decoded,
            tcp_stream,
            udp_stream,
            tcp_events: &tcp_events,
            fragment_events: &fragment_events,
        })
        .map_err(|source| AnalysisError::Sink { number, source })?;
    }

    enforce_deadline(&deadline, limits)?;
    Ok(AnalysisSummary {
        frames_read,
        frames_matched,
        bytes_read,
        tcp_stream_count: tcp_streams.len() as u64,
        udp_stream_count: udp_streams.len() as u64,
        trailing_tcp_events: tcp_reassembler
            .as_mut()
            .map(TcpReassembler::flush)
            .unwrap_or_default(),
        trailing_fragment_events: fragments.flush(),
    })
}

fn enforce_deadline(deadline: &Deadline, limits: &AnalysisLimits) -> Result<(), AnalysisError> {
    deadline
        .check()
        .map_err(|error| AnalysisError::DurationLimit {
            actual: error.actual,
            limit: limits.max_duration,
        })
}

/// Maps capture timestamps onto the monotonic instants reassembly expects.
///
/// The first frame anchors the scale and later frames advance by their
/// distance from it, so idle expiry follows the capture's own clock. A
/// timestamp that runs backwards clamps to the latest instant already
/// issued, never rewinding idle accounting.
struct CaptureClock {
    base: Instant,
    origin: Option<SystemTime>,
    latest: Instant,
    swept: Option<Instant>,
}

/// How far capture time must advance before a pushless frame sweeps again.
///
/// Sweeping scans every buffered flow, so doing it on every frame would make
/// a dense capture quadratic. Frames that push into a reassembler always
/// expire first regardless of this throttle — that is what keeps expiry
/// boundaries exact — so the throttle only paces the release of idle state
/// while nothing is being pushed, where a one-second lag is harmless.
const SWEEP_GRANULARITY: Duration = Duration::from_secs(1);

impl CaptureClock {
    fn new() -> Self {
        let base = Instant::now();
        Self {
            base,
            origin: None,
            latest: base,
            swept: None,
        }
    }

    /// Returns a monotonic instant for `timestamp`: never earlier than any
    /// instant already returned, so a capture whose timestamps run backwards
    /// cannot rewind idle accounting and expire still-active state early.
    fn at(&mut self, timestamp: SystemTime) -> Instant {
        let origin = *self.origin.get_or_insert(timestamp);
        let offset = timestamp.duration_since(origin).unwrap_or(Duration::ZERO);
        self.latest = self
            .base
            .checked_add(offset)
            .unwrap_or(self.base)
            .max(self.latest);
        self.latest
    }

    /// Whether capture time has advanced enough to justify an expiry sweep.
    fn should_sweep(&mut self, now: Instant) -> bool {
        let due = self
            .swept
            .is_none_or(|swept| now.saturating_duration_since(swept) >= SWEEP_GRANULARITY);
        if due {
            self.swept = Some(now);
        }
        due
    }
}
