// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The bounded read → dissect → IP reassemble → index → filter → TCP dispatch
//! loop shared by the offline analysis commands.

use std::io::Read;
use std::mem::size_of;
use std::sync::Arc;

use crate::analysis::pcap::{Error as CaptureError, Reader};
use crate::budget::Deadline;
use crate::decode::{DecodedPacket, Dissector};
use crate::filter::{Context as FilterContext, DerivedPacket as FilterDerivedPacket};
use crate::registry::Registry;

use crate::analysis::Error;
use crate::analysis::adapter::{
    ip_fragments, ip_fragments_in_scope, replayed_ip_prefix_layers, tcp_segment, transports,
    udp_flow,
};
use crate::analysis::conversation_index::StreamIndex;
use crate::analysis::reassembly::Limits as ReassemblyLimits;
use crate::analysis::reassembly::ip::{
    CompletedDatagram, DatagramKey, Error as IpReassemblyError, ResourceError as IpResourceError,
};
use crate::analysis::reassembly::tcp::{Event as TcpEvent, ScopedFlowKey};
use crate::analysis::scope::{Interner, ScopeId};
use crate::frame::{Frame, LinkType};

mod clock;
mod dispatch;
mod ip;
mod limits;

pub use ip::{
    IpCounters, IpDatagramOutcome, IpEvent, IpEventRecord, IpFamilyCounters, IpReassemblyReport,
};
pub use limits::{Limits, Options};

use clock::CaptureClock;
use dispatch::ReassemblyDispatch;
use ip::IpDispatch;

/// A complete datagram decoded separately from, and attributed to, the
/// physical fragment whose arrival filled its final gap.
#[derive(Debug)]
pub struct DerivedDatagram {
    pub decoded: DecodedPacket,
    pub scope: ScopeId,
    pub fragment_count: usize,
    pub unique_bytes: usize,
    pub payload_bytes: usize,
    replayed_prefix_layers: usize,
}

impl DerivedDatagram {
    pub(crate) const fn replayed_prefix_layers(&self) -> usize {
        self.replayed_prefix_layers
    }
}

/// One matched frame, dispatched in capture order.
#[derive(Debug)]
pub struct FrameRecord<'a> {
    /// 1-based position in the capture, counting unmatched frames too, so
    /// numbers agree with every other command reading the same file.
    pub number: u64,
    pub decoded: &'a DecodedPacket,
    derived_datagrams: &'a [DerivedDatagram],
    /// Conversation index of the innermost TCP flow, when there is one.
    pub tcp_stream: Option<u64>,
    /// Exact scoped identity corresponding to `tcp_stream`.
    pub tcp_flow: Option<&'a ScopedFlowKey>,
    /// Conversation index of the innermost UDP flow, when there is one.
    pub udp_stream: Option<u64>,
    /// Exact scoped identity corresponding to `udp_stream`.
    pub udp_flow: Option<&'a ScopedFlowKey>,
    /// TCP reassembly events this frame produced, when requested, including
    /// evictions of flows whose idle expiry this frame's arrival revealed.
    pub tcp_events: &'a [TcpEvent],
    /// Decoded view that supplied this record's innermost TCP transport.
    pub tcp_decoded: &'a DecodedPacket,
    /// Decoded view that supplied this record's innermost UDP transport.
    pub udp_decoded: &'a DecodedPacket,
}

impl FrameRecord<'_> {
    /// Innermost completed network-layer view attached to this physical
    /// frame. It is never a second physical pipeline record and never
    /// contributes bytes to physical capture accounting.
    #[must_use]
    pub fn derived(&self) -> Option<&DerivedDatagram> {
        self.derived_datagrams.last()
    }

    /// All completed datagram views attached to this physical frame, ordered
    /// from outermost to innermost.
    #[must_use]
    pub fn derived_datagrams(&self) -> &[DerivedDatagram] {
        self.derived_datagrams
    }
}

/// Terminal counters and residue for a completed analysis run.
#[derive(Clone, Debug)]
pub struct Summary {
    pub frames_read: u64,
    pub frames_matched: u64,
    /// Data still buffered when the capture ended, flushed flow by flow.
    /// Streams that never saw FIN or RST surface their bytes here.
    pub trailing_tcp_events: Vec<TcpEvent>,
    /// Capture-global bounded fragment counters and retained datagram
    /// outcomes, including bounded EOF incomplete outcomes, which the IP
    /// event sink also observes. Additional outcomes increment
    /// `outcomes_omitted`.
    pub ip_reassembly: IpReassemblyReport,
}

/// Runs the shared analysis loop, dispatching each matched frame to `sink`.
///
/// The reader arrives configured with its own per-frame and interface
/// bounds; this loop enforces the aggregate frame, byte, flow, and duration
/// budgets, dissects under `limits.max_frame_bytes`, advances capture-global
/// IP reassembly, assigns conversation indices to physical or derived
/// transports, applies the filter, and drives TCP reassembly for frames the
/// filter keeps.
///
/// Reassembly follows capture time, not wall-clock time: idle expiry is
/// measured between frame timestamps, so analyzing an old capture behaves
/// the same today as it did the day it was recorded.
pub fn run<R, F>(
    reader: &mut Reader<R>,
    registry: Arc<Registry>,
    options: &Options<'_>,
    sink: F,
) -> Result<Summary, Error>
where
    R: Read,
    F: FnMut(FrameRecord<'_>) -> Result<(), crate::error::BoundaryError>,
{
    run_with_ip_events(reader, registry, options, |_| Ok(()), sink)
}

/// [`run`], additionally delivering capture-global IP lifecycle events before
/// any downstream record enabled by the same physical frame.
///
/// Unlike the matched-frame sink, `ip_sink` observes bounded events revealed
/// by every physical frame and by the EOF flush. Additional outcomes remain
/// reflected in counters and `outcomes_omitted`. This keeps fragment
/// accounting faithful when a display filter narrows transport analysis.
pub fn run_with_ip_events<R, I, F>(
    reader: &mut Reader<R>,
    registry: Arc<Registry>,
    options: &Options<'_>,
    mut ip_sink: I,
    mut sink: F,
) -> Result<Summary, Error>
where
    R: Read,
    I: FnMut(IpEventRecord) -> Result<(), crate::error::BoundaryError>,
    F: FnMut(FrameRecord<'_>) -> Result<(), crate::error::BoundaryError>,
{
    options.limits.validate()?;
    let limits = &options.limits;
    let deadline = Deadline::new(limits.max_duration);
    let decoder = Dissector::new(registry);
    let mut tcp_streams = StreamIndex::default();
    let mut udp_streams = StreamIndex::default();
    // One physical frame can introduce at most a fragment base scope plus one
    // TCP and one UDP analysis scope. Tying the persistent interner to the
    // input frame budget avoids changing the meaning of the per-transport
    // flow and concurrent-datagram ceilings.
    let scope_limit = usize::try_from(limits.max_frames)
        .unwrap_or(usize::MAX)
        .saturating_mul(3);
    let mut scopes = Interner::with_limit(scope_limit);
    let mut reassembly_dispatch = ReassemblyDispatch::new(options.tcp_events, limits.max_flows);
    let mut ip_dispatch = IpDispatch::new(
        ReassemblyLimits {
            max_ip_datagrams: limits.max_ip_datagrams,
            max_ip_fragments_per_datagram: limits.max_ip_fragments_per_datagram,
            max_ip_bytes_per_datagram: limits.max_ip_bytes_per_datagram,
            max_ip_aggregate_bytes: limits.max_ip_reassembly_bytes,
            max_ip_retained_outcomes: limits.max_ip_outcomes,
            ip_idle_expiry: limits.ip_idle_expiry,
            ..ReassemblyLimits::default()
        },
        options.ip_overlap,
        limits.max_ip_outcomes,
    );
    let mut ip_clock = CaptureClock::new();
    let mut tcp_clock = CaptureClock::new();

    let mut frames_read = 0_u64;
    let mut frames_matched = 0_u64;
    let mut bytes_read = 0_u64;
    loop {
        enforce_deadline(&deadline, limits)?;
        let Some((number, frame, timestamp)) =
            next_frame(reader, &mut frames_read, &mut bytes_read, limits)?
        else {
            break;
        };
        let decoded = decoder
            .decode(
                frame,
                crate::decode::Options {
                    max_packet_size: limits.max_frame_bytes,
                    ..crate::decode::Options::default()
                },
            )
            .map_err(|source| Error::Decode { number, source })?;

        // Every physical frame advances capture-global IP state before any
        // transport indexing or display filter. A completion is decoded as a
        // derived network-layer view attributed to this same physical frame.
        let now = ip_clock.at(timestamp, number)?;
        let expired = ip_dispatch.expire(now);
        for event in expired {
            enforce_deadline(&deadline, limits)?;
            ip_sink(IpEventRecord { number, event })
                .map_err(|source| Error::Sink { number, source })?;
        }
        let fragments = ip_fragments(&decoded, &mut scopes)
            .map_err(|source| Error::Scope { number, source })?;
        let (mut completed, next_events) = ip_dispatch
            .dispatch(fragments, now, 0)
            .map_err(|source| Error::IpReassembly { number, source })?;
        for event in next_events {
            enforce_deadline(&deadline, limits)?;
            ip_sink(IpEventRecord { number, event })
                .map_err(|source| Error::Sink { number, source })?;
        }
        let mut derived = Vec::new();
        let mut derived_memory_charge = 0;
        while let Some(datagram) = completed {
            enforce_deadline(&deadline, limits)?;
            let source = derived
                .last()
                .map_or(&decoded, |derived: &DerivedDatagram| &derived.decoded);
            let decode_budget = plan_derived_decode(
                derived_memory_charge,
                datagram.bytes.len(),
                ip_dispatch.retained_memory_charge(),
                limits.max_ip_reassembly_bytes,
            )
            .map_err(|source| Error::IpReassembly { number, source })?;
            let next_derived = decode_derived(
                &decoder,
                source,
                datagram,
                number,
                decode_budget.max_layers,
                decode_budget.budget_reduced,
                limits.max_ip_reassembly_bytes,
            )?;
            let next_derived_memory_charge = charge_derived_memory(
                derived_memory_charge,
                decode_budget.charge,
                ip_dispatch.retained_memory_charge(),
                limits.max_ip_reassembly_bytes,
            )
            .map_err(|source| Error::IpReassembly { number, source })?;
            let fragments = ip_fragments_in_scope(
                &next_derived.decoded,
                source,
                next_derived.scope,
                &mut scopes,
            )
            .map_err(|source| Error::Scope { number, source })?;
            let (next_completed, next_events) = ip_dispatch
                .dispatch(fragments, now, next_derived_memory_charge)
                .map_err(|source| Error::IpReassembly { number, source })?;
            for event in next_events {
                enforce_deadline(&deadline, limits)?;
                ip_sink(IpEventRecord { number, event })
                    .map_err(|source| Error::Sink { number, source })?;
            }
            derived.push(next_derived);
            derived_memory_charge = next_derived_memory_charge;
            completed = next_completed;
        }
        // One transport walk per derived view; the innermost occurrence of
        // each transport kind wins, so later views overwrite earlier ones.
        let mut derived_tcp = None;
        let mut derived_udp = None;
        for (index, derived_datagram) in derived.iter().enumerate() {
            let found = transports(&derived_datagram.decoded.packet);
            if found.tcp.is_some() {
                derived_tcp = Some((index, derived_datagram));
            }
            if found.udp.is_some() {
                derived_udp = Some((index, derived_datagram));
            }
        }
        let tcp_decoded = derived_tcp.map_or(&decoded, |(_, derived)| &derived.decoded);
        let udp_decoded = derived_udp.map_or(&decoded, |(_, derived)| &derived.decoded);
        let scope_base = |entry: Option<(usize, &DerivedDatagram)>| {
            entry.map(|(index, derived_datagram)| {
                (
                    derived_source(&decoded, &derived, index),
                    derived_datagram.scope,
                )
            })
        };

        // Assign stream IDs before filtering to keep them stable across runs.
        let segment = tcp_segment(tcp_decoded, scope_base(derived_tcp), &mut scopes)
            .map_err(|source| Error::Scope { number, source })?;
        let tcp_stream = match &segment {
            Some(segment) => Some(tcp_streams.assign(&segment.flow, number, limits.max_flows)?),
            None => None,
        };
        let udp_flow = udp_flow(udp_decoded, scope_base(derived_udp), &mut scopes)
            .map_err(|source| Error::Scope { number, source })?;
        let udp_stream = match &udp_flow {
            Some(flow) => Some(udp_streams.assign(flow, number, limits.max_flows)?),
            None => None,
        };
        let filter_derived = derived
            .iter()
            .map(|derived| FilterDerivedPacket {
                decoded: &derived.decoded,
                replayed_prefix_layers: derived.replayed_prefix_layers,
            })
            .collect::<Vec<_>>();

        if let Some(filter) = options.filter
            && !filter
                .matches(&FilterContext {
                    decoded: &decoded,
                    derived: &filter_derived,
                    number,
                    tcp_stream,
                    udp_stream,
                })
                .map_err(|source| Error::Filter { number, source })?
        {
            continue;
        }
        frames_matched = frames_matched.saturating_add(1);

        let tcp_events = reassembly_dispatch.dispatch(
            tcp_decoded,
            segment.as_ref(),
            timestamp,
            number,
            &mut tcp_clock,
            limits.max_flows,
        )?;

        enforce_deadline(&deadline, limits)?;
        sink(FrameRecord {
            number,
            decoded: &decoded,
            derived_datagrams: &derived,
            tcp_stream,
            tcp_flow: segment.as_ref().map(|segment| &segment.flow),
            udp_stream,
            udp_flow: udp_flow.as_ref(),
            tcp_events: &tcp_events,
            tcp_decoded,
            udp_decoded,
        })
        .map_err(|source| Error::Sink { number, source })?;
    }

    enforce_deadline(&deadline, limits)?;
    for event in ip_dispatch.flush() {
        enforce_deadline(&deadline, limits)?;
        ip_sink(IpEventRecord {
            number: frames_read,
            event,
        })
        .map_err(|source| Error::Sink {
            number: frames_read,
            source,
        })?;
    }
    enforce_deadline(&deadline, limits)?;
    Ok(Summary {
        frames_read,
        frames_matched,
        trailing_tcp_events: reassembly_dispatch.flush(),
        ip_reassembly: ip_dispatch.report().clone(),
    })
}

fn derived_source<'a>(
    physical: &'a DecodedPacket,
    derived: &'a [DerivedDatagram],
    index: usize,
) -> &'a DecodedPacket {
    index
        .checked_sub(1)
        .and_then(|index| derived.get(index))
        .map_or(physical, |derived| &derived.decoded)
}

fn charge_derived_memory(
    current: usize,
    datagram_bytes: usize,
    retained: usize,
    limit: usize,
) -> Result<usize, IpReassemblyError> {
    let derived = current
        .checked_add(datagram_bytes)
        .ok_or(IpResourceError::AggregateMemoryLimit { limit })?;
    retained
        .checked_add(derived)
        .filter(|total| *total <= limit)
        .ok_or(IpResourceError::AggregateMemoryLimit { limit })?;
    Ok(derived)
}

struct DerivedDecodeBudget {
    charge: usize,
    max_layers: usize,
    budget_reduced: bool,
}

fn plan_derived_decode(
    current: usize,
    datagram_bytes: usize,
    retained: usize,
    limit: usize,
) -> Result<DerivedDecodeBudget, IpReassemblyError> {
    // Each committed layer consumes at least one input byte; only the final
    // stop layer may consume zero. Capping the decoder to the number of layers
    // reserved here makes the pre-allocation charge enforceable.
    const LAYER_METADATA_RESERVATION: usize = 4_096;

    let occupied = current
        .checked_add(retained)
        .ok_or_else(|| aggregate_memory_error(limit))?;
    let available = limit
        .checked_sub(occupied)
        .ok_or_else(|| aggregate_memory_error(limit))?;
    let base_charge = datagram_bytes
        .checked_add(size_of::<DecodedPacket>())
        .and_then(|charge| {
            size_of::<DerivedDatagram>()
                .checked_mul(2)
                .and_then(|metadata| charge.checked_add(metadata))
        })
        .ok_or_else(|| aggregate_memory_error(limit))?;
    let per_layer_charge = datagram_bytes
        .checked_mul(2)
        .and_then(|charge| charge.checked_add(size_of::<Box<dyn crate::layer::Layer>>()))
        .and_then(|charge| charge.checked_add(size_of::<Option<usize>>()))
        .and_then(|charge| charge.checked_add(LAYER_METADATA_RESERVATION))
        .ok_or_else(|| aggregate_memory_error(limit))?;
    let structural_layers = crate::decode::Options::default()
        .max_layers
        .min(datagram_bytes.saturating_add(1));
    let affordable_layers = available
        .checked_sub(base_charge)
        .and_then(|remaining| remaining.checked_div(per_layer_charge))
        .unwrap_or(0);
    let max_layers = structural_layers.min(affordable_layers);
    if max_layers == 0 {
        return Err(aggregate_memory_error(limit));
    }
    let charge = per_layer_charge
        .checked_mul(max_layers)
        .and_then(|metadata| base_charge.checked_add(metadata))
        .ok_or_else(|| aggregate_memory_error(limit))?;
    Ok(DerivedDecodeBudget {
        charge,
        max_layers,
        budget_reduced: max_layers < structural_layers,
    })
}

fn aggregate_memory_error(limit: usize) -> IpReassemblyError {
    IpResourceError::AggregateMemoryLimit { limit }.into()
}

fn decode_derived(
    decoder: &Dissector,
    source: &DecodedPacket,
    datagram: CompletedDatagram,
    number: u64,
    max_layers: usize,
    budget_reduced: bool,
    memory_limit: usize,
) -> Result<DerivedDatagram, Error> {
    let (scope, link_type) = match &datagram.key {
        DatagramKey::Ipv4(key) => (key.scope, LinkType::IPV4),
        DatagramKey::Ipv6(key) => (key.scope, LinkType::IPV6),
    };
    let timestamp = source
        .frame
        .timestamp
        .ok_or(Error::TimestampUnavailable { number })?;
    let mut frame = Frame::new(timestamp, link_type, datagram.bytes.clone())
        .map_err(|source| Error::DerivedFrame { number, source })?;
    frame.interface = source.frame.interface;
    frame.direction = source.frame.direction;
    let decoded = decoder
        .decode(
            frame,
            crate::decode::Options {
                max_layers,
                max_packet_size: datagram.bytes.len(),
            },
        )
        .map_err(|source| {
            if budget_reduced
                && matches!(&source, crate::decode::Error::LayerLimit { limit } if *limit == max_layers)
            {
                Error::IpReassembly {
                    number,
                    source: IpResourceError::AggregateMemoryLimit {
                        limit: memory_limit,
                    }
                    .into(),
                }
            } else {
                Error::DerivedDecode { number, source }
            }
        })?;
    Ok(DerivedDatagram {
        decoded,
        scope,
        fragment_count: datagram.fragment_count,
        unique_bytes: datagram.unique_bytes,
        payload_bytes: datagram.final_payload_length,
        replayed_prefix_layers: replayed_ip_prefix_layers(source),
    })
}

fn next_frame<R: Read>(
    reader: &mut Reader<R>,
    frames_read: &mut u64,
    bytes_read: &mut u64,
    limits: &Limits,
) -> Result<Option<(u64, crate::frame::Frame, std::time::SystemTime)>, Error> {
    let number = frames_read.checked_add(1).ok_or(Error::Capture {
        number: *frames_read,
        source: CaptureError::FrameLimitExceeded {
            actual: u64::MAX,
            limit: limits.max_frames,
        },
    })?;
    let Some(frame) = reader
        .next_frame()
        .map_err(|source| Error::Capture { number, source })?
    else {
        return Ok(None);
    };
    *frames_read = number;
    if number > limits.max_frames {
        return Err(Error::Capture {
            number,
            source: CaptureError::FrameLimitExceeded {
                actual: number,
                limit: limits.max_frames,
            },
        });
    }
    let captured = u64::from(frame.captured_length());
    *bytes_read = bytes_read
        .checked_add(captured)
        .filter(|bytes| *bytes <= limits.max_bytes)
        .ok_or(Error::Capture {
            number,
            source: CaptureError::StreamByteLimitExceeded {
                actual: bytes_read.saturating_add(captured),
                limit: limits.max_bytes,
            },
        })?;
    let timestamp = frame
        .timestamp
        .ok_or(Error::TimestampUnavailable { number })?;
    Ok(Some((number, frame, timestamp)))
}

fn enforce_deadline(deadline: &Deadline, limits: &Limits) -> Result<(), Error> {
    deadline.check().map_err(|error| Error::DurationLimit {
        actual: error.actual,
        limit: limits.max_duration,
    })
}
