// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The bounded read → dissect → IP reassemble → index → filter → TCP dispatch
//! loop shared by the offline analysis commands.

use std::io::Read;
use std::sync::Arc;
use std::time::SystemTime;

use crate::analysis::pcap::Reader;
use crate::budget::Deadline;
use crate::decode::{DecodedPacket, Dissector};
use crate::filter::{Context as FilterContext, DerivedPacket as FilterDerivedPacket};
use crate::registry::Registry;

use crate::analysis::Error;
use crate::analysis::adapter::{
    TcpTransport, UdpTransport, ip_fragments, ip_fragments_in_scope, replayed_ip_prefix_layers,
    tcp_segment, transports, udp_flow,
};
use crate::analysis::conversation_index::StreamIndex;
use crate::analysis::reassembly::ip::{
    CompletedDatagram, DatagramKey, ResourceError as IpResourceError,
};
use crate::analysis::reassembly::tcp::{Event as TcpEvent, ScopedFlowKey};
use crate::analysis::scope::{Interner, ScopeId};
use crate::frame::{Frame, LinkType};
use crate::protocol::transport::Tcp;

mod clock;
mod dispatch;
mod ip;
mod limits;

pub use ip::{
    IpCounters, IpDatagramOutcome, IpEvent, IpEventRecord, IpFamilyCounters, IpReassemblyReport,
};
pub use limits::{Limits, Options};

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
    /// The frame's capture timestamp, already validated as present by the
    /// loop that read it. Every time-dependent consumer reads it from here
    /// rather than re-deriving it and inventing its own failure case.
    pub timestamp: SystemTime,
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
    /// Layer position of the innermost TCP header within `tcp_decoded`.
    /// Present whenever the view carries TCP, even when the header is the
    /// visible carrier of a fragmented child and so has no `tcp_flow`.
    pub tcp_layer: Option<usize>,
    /// The innermost TCP header within `tcp_decoded`, located once by the
    /// pipeline. Present under the same condition as `tcp_layer`.
    pub tcp_header: Option<&'a Tcp>,
    /// Exact TCP stream bytes this frame carried, and 0 when it carried no
    /// indexed TCP segment. Pure control segments legitimately carry none.
    pub tcp_payload_len: usize,
    /// Layer position of the innermost UDP header within `udp_decoded`,
    /// under the same condition as `tcp_layer`.
    pub udp_layer: Option<usize>,
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
///
/// Every collector closes its pass with this one value, so the trailing
/// events and the frame number a finding is attributed to cannot be supplied
/// separately and cannot disagree.
#[derive(Clone, Debug, Default)]
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
    let mut reassembly_dispatch = ReassemblyDispatch::new(options.tcp_events, limits);
    let mut ip_dispatch = IpDispatch::new(limits.ip_reassembly(), options.ip_overlap);
    let stage = FrameStage {
        decoder: &decoder,
        deadline: &deadline,
        max_ip_reassembly_bytes: limits.max_ip_reassembly_bytes,
    };

    let mut frames_read = 0_u64;
    let mut frames_matched = 0_u64;
    let mut bytes_read = 0_u64;
    loop {
        enforce_deadline(&deadline)?;
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
        let derived = advance_ip_reassembly(
            &mut ip_dispatch,
            &stage,
            &mut scopes,
            PhysicalFrame {
                decoded: &decoded,
                number,
                timestamp,
            },
            &mut ip_sink,
        )?;
        let TransportViews { tcp, udp } = elect_transport_views(&decoded, &derived);
        let tcp_decoded = tcp.as_ref().map_or(&decoded, |elected| elected.decoded);
        let udp_decoded = udp.as_ref().map_or(&decoded, |elected| elected.decoded);
        let tcp_layer = tcp.as_ref().map(|elected| elected.transport.index);
        let tcp_header = tcp.as_ref().map(|elected| elected.transport.layer);
        let udp_layer = udp.as_ref().map(|elected| elected.transport.index);
        let scope_base = |derived_index: Option<usize>| {
            derived_index.and_then(|index| {
                derived.get(index).map(|derived_datagram| {
                    (
                        derived_source(&decoded, &derived, index),
                        derived_datagram.scope,
                    )
                })
            })
        };

        // Assign stream IDs before filtering to keep them stable across runs.
        let segment = match tcp {
            Some(elected) => tcp_segment(
                elected.decoded,
                elected.transport,
                scope_base(elected.derived_index),
                &mut scopes,
            )
            .map_err(|source| Error::Scope { number, source })?,
            None => None,
        };
        let tcp_stream = match &segment {
            Some(segment) => Some(tcp_streams.assign(&segment.flow, number, limits.max_flows)?),
            None => None,
        };
        let udp_flow = match udp {
            Some(elected) => udp_flow(
                elected.decoded,
                elected.transport,
                scope_base(elected.derived_index),
                &mut scopes,
            )
            .map_err(|source| Error::Scope { number, source })?,
            None => None,
        };
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

        let tcp_events =
            reassembly_dispatch.dispatch(tcp_header, segment.as_ref(), timestamp, number)?;

        enforce_deadline(&deadline)?;
        sink(FrameRecord {
            number,
            timestamp,
            decoded: &decoded,
            derived_datagrams: &derived,
            tcp_stream,
            tcp_flow: segment.as_ref().map(|segment| &segment.flow),
            udp_stream,
            udp_flow: udp_flow.as_ref(),
            tcp_events: &tcp_events,
            tcp_decoded,
            udp_decoded,
            tcp_layer,
            tcp_header,
            tcp_payload_len: segment.as_ref().map_or(0, |segment| segment.payload.len()),
            udp_layer,
        })
        .map_err(|source| Error::Sink { number, source })?;
    }

    enforce_deadline(&deadline)?;
    for event in ip_dispatch.flush() {
        enforce_deadline(&deadline)?;
        ip_sink(IpEventRecord {
            number: frames_read,
            event,
        })
        .map_err(|source| Error::Sink {
            number: frames_read,
            source,
        })?;
    }
    enforce_deadline(&deadline)?;
    Ok(Summary {
        frames_read,
        frames_matched,
        trailing_tcp_events: reassembly_dispatch.flush(),
        ip_reassembly: ip_dispatch.report().clone(),
    })
}

/// Loop-invariant state the per-frame stages share.
struct FrameStage<'a> {
    decoder: &'a Dissector,
    deadline: &'a Deadline,
    max_ip_reassembly_bytes: usize,
}

/// One physical frame, as the stages downstream of the reader see it.
struct PhysicalFrame<'a> {
    decoded: &'a DecodedPacket,
    number: u64,
    timestamp: SystemTime,
}

/// Advances capture-global IP reassembly for one physical frame, returning
/// the derived datagram views its arrival completed, outermost first.
///
/// Every lifecycle event this reveals reaches `ip_sink` before the frame's
/// own record does, and the run deadline is checked before each one: a sink
/// that blocks must not be able to overrun the budget by staying inside a
/// single batch.
fn advance_ip_reassembly<I>(
    ip_dispatch: &mut IpDispatch,
    stage: &FrameStage<'_>,
    scopes: &mut Interner,
    frame: PhysicalFrame<'_>,
    ip_sink: &mut I,
) -> Result<Vec<DerivedDatagram>, Error>
where
    I: FnMut(IpEventRecord) -> Result<(), crate::error::BoundaryError>,
{
    let PhysicalFrame {
        decoded,
        number,
        timestamp,
    } = frame;
    let emit = |events: Vec<IpEvent>, sink: &mut I| -> Result<(), Error> {
        for event in events {
            enforce_deadline(stage.deadline)?;
            sink(IpEventRecord { number, event })
                .map_err(|source| Error::Sink { number, source })?;
        }
        Ok(())
    };

    let now = ip_dispatch.at(timestamp, number)?;
    emit(ip_dispatch.expire(now), ip_sink)?;
    let fragments =
        ip_fragments(decoded, scopes).map_err(|source| Error::Scope { number, source })?;
    let (mut completed, events) = ip_dispatch
        .dispatch(fragments, now, 0)
        .map_err(|source| Error::IpReassembly { number, source })?;
    emit(events, ip_sink)?;

    let mut derived: Vec<DerivedDatagram> = Vec::new();
    let mut derived_memory_charge = 0;
    while let Some(datagram) = completed {
        enforce_deadline(stage.deadline)?;
        let source = derived.last().map_or(decoded, |derived| &derived.decoded);
        let budget = ip_dispatch
            .plan_derived_decode(derived_memory_charge, datagram.bytes.len())
            .map_err(|source| Error::IpReassembly { number, source })?;
        let next_derived = decode_derived(
            stage.decoder,
            source,
            datagram,
            number,
            budget.max_layers,
            budget.budget_reduced,
            stage.max_ip_reassembly_bytes,
        )?;
        let next_derived_memory_charge = ip_dispatch
            .charge_derived_memory(derived_memory_charge, budget.charge)
            .map_err(|source| Error::IpReassembly { number, source })?;
        let fragments =
            ip_fragments_in_scope(&next_derived.decoded, source, next_derived.scope, scopes)
                .map_err(|source| Error::Scope { number, source })?;
        let (next_completed, events) = ip_dispatch
            .dispatch(fragments, now, next_derived_memory_charge)
            .map_err(|source| Error::IpReassembly { number, source })?;
        emit(events, ip_sink)?;
        derived.push(next_derived);
        derived_memory_charge = next_derived_memory_charge;
        completed = next_completed;
    }
    Ok(derived)
}

/// The transport of one kind a frame's records are attributed to, together
/// with the decoded view it was found in.
struct ElectedTransport<'a, T> {
    /// Position in the derived cascade, or [`None`] for the physical frame.
    derived_index: Option<usize>,
    decoded: &'a DecodedPacket,
    transport: T,
}

struct TransportViews<'a> {
    tcp: Option<ElectedTransport<'a, TcpTransport<'a>>>,
    udp: Option<ElectedTransport<'a, UdpTransport>>,
}

/// Elects the innermost transport of each kind across the physical frame and
/// its derived datagram views.
///
/// One walk per decoded view, and the located transports are carried forward
/// rather than looked up again: a tunnelled frame legitimately belongs to
/// both a UDP conversation and a TCP conversation, and the innermost
/// occurrence of each kind is the one an operator means.
fn elect_transport_views<'a>(
    decoded: &'a DecodedPacket,
    derived: &'a [DerivedDatagram],
) -> TransportViews<'a> {
    let mut views = TransportViews {
        tcp: None,
        udp: None,
    };
    let physical = std::iter::once((None, decoded));
    let cascade = derived
        .iter()
        .enumerate()
        .map(|(index, datagram)| (Some(index), &datagram.decoded));
    for (derived_index, view) in physical.chain(cascade) {
        let found = transports(&view.packet);
        if let Some(transport) = found.tcp {
            views.tcp = Some(ElectedTransport {
                derived_index,
                decoded: view,
                transport,
            });
        }
        if let Some(transport) = found.udp {
            views.udp = Some(ElectedTransport {
                derived_index,
                decoded: view,
                transport,
            });
        }
    }
    views
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

/// Reads one physical frame and charges it against the aggregate frame and
/// captured-byte ceilings, which the capture reader's own [`pcap::Limits`]
/// enforces so this loop does not re-implement them.
fn next_frame<R: Read>(
    reader: &mut Reader<R>,
    frames_read: &mut u64,
    bytes_read: &mut u64,
    limits: &Limits,
) -> Result<Option<(u64, crate::frame::Frame, SystemTime)>, Error> {
    let number = frames_read.saturating_add(1);
    let Some(frame) = reader
        .next_frame()
        .map_err(|source| Error::Capture { number, source })?
    else {
        return Ok(None);
    };
    let (number, bytes) = limits
        .capture()
        .advance(*frames_read, *bytes_read, frame.captured_length())
        .map_err(|source| Error::Capture { number, source })?;
    *frames_read = number;
    *bytes_read = bytes;
    let timestamp = frame
        .timestamp
        .ok_or(Error::TimestampUnavailable { number })?;
    Ok(Some((number, frame, timestamp)))
}

/// Refuses to continue once the run's own processing budget is spent.
///
/// The deadline already carries the limit it was built from, so the duration
/// budget has one owner and callers cannot pass a limit that disagrees with
/// the clock enforcing it.
fn enforce_deadline(deadline: &Deadline) -> Result<(), Error> {
    deadline.check().map_err(|error| Error::DurationLimit {
        actual: error.actual,
        limit: error.limit,
    })
}
