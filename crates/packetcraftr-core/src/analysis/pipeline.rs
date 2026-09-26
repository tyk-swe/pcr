// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The bounded read → dissect → IP reassemble → index → filter → TCP dispatch
//! loop shared by the offline analysis commands.

use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::budget::Deadline;
use crate::capture_file::Reader;
use crate::decode::{DecodedPacket, Dissector};
use crate::filter::{Context as FilterContext, DerivedPacket as FilterDerivedPacket};
use crate::registry::Registry;

use crate::analysis::Error;
use crate::analysis::adapter::{
    TcpTransport, UdpTransport, ip_fragments, ip_fragments_in_scope, replayed_ip_prefix_layers,
    tcp_segment, transports, udp_flow,
};
use crate::analysis::conversation_index::StreamIndex;
use crate::analysis::reassembly::ip::{CompletedDatagram, DatagramKey, Resource as IpResource};
use crate::analysis::reassembly::tcp::{Event as TcpEvent, ScopedFlowKey};
use crate::analysis::scope::{Interner, Limits as ScopeLimits, MAX_SCOPES, ScopeId};
use crate::frame::{Frame, LinkType};
use crate::protocol::transport::Tcp;

mod clock;
mod dispatch;
mod ip;
mod limits;

pub use clock::ClockReport;
pub use ip::{
    IpCounters, IpDatagramOutcome, IpEvent, IpEventRecord, IpFamilyCounters, IpReassemblyReport,
};
pub use limits::{Limits, Options, Plan};

use dispatch::ReassemblyDispatch;
use ip::IpDispatch;

/// A complete datagram decoded separately from, and attributed to, the
/// physical fragment whose arrival filled its final gap.
#[derive(Debug)]
pub struct DerivedDatagram {
    pub sources: Option<crate::analysis::provenance::SourceSet>,
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
    /// loop that read it.
    pub timestamp: SystemTime,
    pub decoded: &'a DecodedPacket,
    derived_datagrams: &'a [DerivedDatagram],
    scopes: &'a Interner,
    physical_sources: Option<&'a crate::analysis::provenance::SourceSet>,
    /// Innermost TCP and UDP observations, each tied to the decoded view
    /// that supplied it. A tunnel can carry one of each.
    pub tcp: Option<TcpView<'a>>,
    pub udp: Option<UdpView<'a>>,
    /// Reassembly events in delivery order, including expiry of other flows.
    pub tcp_events: &'a [TcpEvent],
    /// The rollback this frame's timestamp showed against the capture's
    /// high-water mark, when it regressed. The shared capture clock detects
    /// the regression for every physical frame; matched frames carry it so
    /// downstream evidence can attribute it here.
    pub clock_regression: Option<Duration>,
}

/// A capture-global stream index and the scoped flow it identifies.
#[derive(Clone, Copy, Debug)]
pub struct Conversation<'a> {
    pub index: u64,
    pub flow: &'a ScopedFlowKey,
}

/// One TCP header and its exact source view. A visible carrier of a fragmented
/// TCP child has no conversation until the child can be reconstructed.
#[derive(Clone, Copy, Debug)]
pub struct TcpView<'a> {
    pub decoded: &'a DecodedPacket,
    pub layer: usize,
    pub header: &'a Tcp,
    pub conversation: Option<Conversation<'a>>,
    /// Indexed segment bytes; control segments and unindexed carriers are empty.
    pub payload: &'a [u8],
}

/// One UDP header and its exact source view, with the same carrier convention
/// as [`TcpView`].
#[derive(Clone, Copy, Debug)]
pub struct UdpView<'a> {
    pub decoded: &'a DecodedPacket,
    pub layer: usize,
    pub conversation: Option<Conversation<'a>>,
}

impl FrameRecord<'_> {
    pub fn physical_sources(&self) -> Option<&crate::analysis::provenance::SourceSet> {
        self.physical_sources
    }
    pub fn tcp_sources(&self) -> Option<&crate::analysis::provenance::SourceSet> {
        self.tcp.and_then(|view| self.sources_of(view.decoded))
    }
    pub fn udp_sources(&self) -> Option<&crate::analysis::provenance::SourceSet> {
        self.udp.and_then(|view| self.sources_of(view.decoded))
    }
    fn sources_of(
        &self,
        decoded: &DecodedPacket,
    ) -> Option<&crate::analysis::provenance::SourceSet> {
        if std::ptr::eq(decoded, self.decoded) {
            return self.physical_sources;
        }
        self.derived_datagrams
            .iter()
            .find(|datagram| std::ptr::eq(&datagram.decoded, decoded))
            .and_then(|datagram| datagram.sources.as_ref())
    }

    /// Filter context containing only this physical frame's packet and indexes.
    pub fn physical_context(&self) -> crate::filter::Context<'_> {
        crate::filter::Context {
            decoded: self.decoded,
            derived: &[],
            number: self.number,
            tcp_stream: self
                .tcp
                .filter(|view| std::ptr::eq(view.decoded, self.decoded))
                .and_then(|view| view.conversation.map(|conversation| conversation.index)),
            udp_stream: self
                .udp
                .filter(|view| std::ptr::eq(view.decoded, self.decoded))
                .and_then(|view| view.conversation.map(|conversation| conversation.index)),
        }
    }

    /// Projects physical and newly reconstructed fields using scoped stream indexes.
    pub fn project(
        &self,
        projection: &crate::filter::Projection,
        max_bytes: usize,
    ) -> Result<Vec<Option<crate::field::FieldValue>>, crate::filter::Error> {
        self.with_filter_context(|context| projection.values(context, max_bytes))
    }

    /// Evaluates a filter against this physical record and its reconstructed children.
    pub fn matches(&self, filter: &crate::filter::Filter) -> Result<bool, crate::filter::Error> {
        self.with_filter_context(|context| filter.matches(context))
    }

    fn with_filter_context<T>(&self, visit: impl FnOnce(&crate::filter::Context<'_>) -> T) -> T {
        let derived: Vec<_> = self
            .derived_datagrams
            .iter()
            .map(|datagram| crate::filter::DerivedPacket {
                decoded: &datagram.decoded,
                replayed_prefix_layers: datagram.replayed_prefix_layers,
            })
            .collect();
        visit(&crate::filter::Context {
            decoded: self.decoded,
            derived: &derived,
            number: self.number,
            tcp_stream: self
                .tcp
                .and_then(|view| view.conversation.map(|conversation| conversation.index)),
            udp_stream: self
                .udp
                .and_then(|view| view.conversation.map(|conversation| conversation.index)),
        })
    }

    /// Resolves a run-local scope into its capture interface and tunnel path.
    pub fn scope_definition(&self, id: ScopeId) -> Option<&crate::analysis::scope::Definition> {
        self.scopes.definition(id)
    }

    /// Capture-global scope definitions observed through this frame.
    pub fn scope_definitions(&self) -> &[crate::analysis::scope::Definition] {
        self.scopes.definitions()
    }

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
    pub incomplete_sources: Vec<crate::analysis::provenance::IncompleteSources>,
    pub source_outcomes_omitted: u64,
    pub clock: ClockReport,
    pub frames_read: u64,
    /// Captured bytes charged to input budgets, including excluded frames.
    pub bytes_read: u64,
    pub frames_matched: u64,
    /// Data still buffered when the capture ended, flushed flow by flow.
    /// Streams that never saw FIN or RST surface their bytes here.
    pub trailing_tcp_events: Vec<TcpEvent>,
    /// Capture-global bounded fragment counters and retained datagram
    /// outcomes, including bounded EOF incomplete outcomes, which the IP
    /// event sink also observes. Additional outcomes increment
    /// `outcomes_omitted`.
    pub ip_reassembly: IpReassemblyReport,
    /// Source interfaces in global [`crate::frame::Frame::interface`] order.
    /// Classic PCAP has one entry; PCAPNG without interface-description blocks
    /// has none.
    pub interfaces: Vec<crate::capture_file::Interface>,
    /// Every capture scope interned during the run, including scopes of
    /// frames the sink never saw, which `incomplete_sources` keys may name.
    pub scopes: Vec<crate::analysis::scope::Definition>,
}

/// Dispatches matched frames to `sink`: dissects under
/// `limits.max_frame_bytes`, updates capture-global IP state and conversation
/// indices, filters, then drives TCP reassembly. Enforces aggregate frame,
/// byte, flow, and processing-duration budgets; reader options bound individual
/// frames and interfaces.
///
/// Reassembly idle expiry follows capture timestamps, independent of wall-clock
/// time.
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
    ip_sink: I,
    sink: F,
) -> Result<Summary, Error>
where
    R: Read,
    I: FnMut(IpEventRecord) -> Result<(), crate::error::BoundaryError>,
    F: FnMut(FrameRecord<'_>) -> Result<(), crate::error::BoundaryError>,
{
    options.limits.validate()?;
    let previous = reader.deadline();
    let deadline = Arc::new(
        Deadline::new(options.limits.max_duration)
            .with_cancellation(options.cancellation.clone())
            .with_parent(options.deadline.clone())
            .with_parent(previous.clone()),
    );
    // `next_frame` may consume arbitrarily many metadata records. Give those
    // record boundaries the same phase and invocation clocks as packet work.
    reader.replace_deadline(Some(deadline.clone()));
    let scope = ReaderDeadlineScope { reader, previous };
    run_inner(
        &mut *scope.reader,
        registry,
        options,
        deadline,
        ip_sink,
        sink,
    )
}

struct ReaderDeadlineScope<'a, R: Read> {
    reader: &'a mut Reader<R>,
    previous: Option<Arc<Deadline>>,
}

impl<R: Read> Drop for ReaderDeadlineScope<'_, R> {
    fn drop(&mut self) {
        self.reader.replace_deadline(self.previous.take());
    }
}

fn run_inner<R, I, F>(
    reader: &mut Reader<R>,
    registry: Arc<Registry>,
    options: &Options<'_>,
    deadline: Arc<Deadline>,
    mut ip_sink: I,
    mut sink: F,
) -> Result<Summary, Error>
where
    R: Read,
    I: FnMut(IpEventRecord) -> Result<(), crate::error::BoundaryError>,
    F: FnMut(FrameRecord<'_>) -> Result<(), crate::error::BoundaryError>,
{
    let limits = &options.limits;
    let decoder = Dissector::new(registry);
    let mut tcp_streams = StreamIndex::default();
    let mut udp_streams = StreamIndex::default();
    // One physical frame can introduce at most a fragment base scope plus one
    // TCP and one UDP analysis scope. Tying the persistent interner to the
    // input frame budget avoids changing the meaning of the per-transport
    // flow and concurrent-datagram ceilings.
    // The identity space bounds the table no matter how many frames the
    // input may carry, so the derived count stops there.
    let max_scopes = usize::try_from(limits.max_frames)
        .unwrap_or(usize::MAX)
        .saturating_mul(3)
        .min(MAX_SCOPES);
    let mut scopes = Interner::with_limits(ScopeLimits {
        max_scopes,
        max_bytes: limits.max_scope_bytes,
    })
    .map_err(|source| Error::Scope { number: 0, source })?;
    let mut reassembly_dispatch = ReassemblyDispatch::new(options.tcp_events, limits)?;
    let mut ip_dispatch = IpDispatch::new(limits.ip.clone(), options.ip_overlap)?;
    let mut provenance = options
        .track_sources
        .then(|| {
            crate::analysis::provenance::Tracker::new(
                limits.max_provenance_bytes,
                limits.ip.max_retained_outcomes,
            )
        })
        .transpose()?;
    let stage = FrameStage {
        decoder: &decoder,
        deadline: &deadline,
        max_ip_reassembly_bytes: limits.ip.max_aggregate_bytes,
    };

    let mut input = limits.capture_budget()?;
    let mut frames_matched = 0_u64;
    loop {
        enforce_deadline(&deadline)?;
        let Some((number, frame)) = next_frame(reader, &mut input)? else {
            break;
        };
        let timestamp = match frame.timestamp {
            Some(timestamp) => timestamp,
            None if options.time_bounds.is_some() => continue,
            None => return Err(Error::TimestampUnavailable { number }),
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
        let physical_sources = provenance
            .as_ref()
            .map(|tracker| {
                tracker.single(crate::analysis::provenance::SourceFrame { number, timestamp })
            })
            .transpose()?;
        let (derived, clock_regression) = if options.plan.ip_reassembly || options.track_sources {
            advance_ip_reassembly(
                &mut ip_dispatch,
                &stage,
                &mut scopes,
                PhysicalFrame {
                    decoded: &decoded,
                    number,
                    timestamp,
                },
                &mut ip_sink,
                &mut provenance,
                physical_sources.as_ref(),
            )?
        } else {
            (Vec::new(), None)
        };
        let TransportViews { tcp, udp } = elect_transport_views(&decoded, &derived);
        let mut tcp_view = tcp.as_ref().map(|elected| TcpView {
            decoded: elected.decoded,
            layer: elected.transport.index,
            header: elected.transport.layer,
            conversation: None,
            payload: &[],
        });
        let mut udp_view = udp.as_ref().map(|elected| UdpView {
            decoded: elected.decoded,
            layer: elected.transport.index,
            conversation: None,
        });
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
        let segment = match tcp.filter(|_| options.plan.tcp_index || options.tcp_events) {
            Some(elected) => tcp_segment(
                elected.decoded,
                elected.transport,
                scope_base(elected.derived_index),
                &mut scopes,
            )
            .map_err(|source| Error::Scope { number, source })?,
            None => None,
        };
        if let (Some(view), Some(segment)) = (&mut tcp_view, &segment) {
            view.conversation = Some(Conversation {
                index: tcp_streams.assign(&segment.flow, number, limits.max_flows)?,
                flow: &segment.flow,
            });
            view.payload = &segment.payload;
        }
        let udp_flow = match udp.filter(|_| options.plan.udp_index) {
            Some(elected) => udp_flow(
                elected.decoded,
                elected.transport,
                scope_base(elected.derived_index),
                &mut scopes,
            )
            .map_err(|source| Error::Scope { number, source })?,
            None => None,
        };
        if let (Some(view), Some(flow)) = (&mut udp_view, &udp_flow) {
            view.conversation = Some(Conversation {
                index: udp_streams.assign(flow, number, limits.max_flows)?,
                flow,
            });
        }
        if let Some(bounds) = options.time_bounds
            && !bounds.contains(Some(timestamp))
        {
            continue;
        }
        if let Some(filter) = options.filter {
            let filter_derived = derived
                .iter()
                .map(|derived| FilterDerivedPacket {
                    decoded: &derived.decoded,
                    replayed_prefix_layers: derived.replayed_prefix_layers,
                })
                .collect::<Vec<_>>();
            if !filter
                .matches(&FilterContext {
                    decoded: &decoded,
                    derived: &filter_derived,
                    number,
                    tcp_stream: tcp_view
                        .and_then(|view| view.conversation)
                        .map(|stream| stream.index),
                    udp_stream: udp_view
                        .and_then(|view| view.conversation)
                        .map(|stream| stream.index),
                })
                .map_err(|source| Error::Filter { number, source })?
            {
                continue;
            }
        }
        frames_matched = frames_matched.saturating_add(1);

        let tcp_events = reassembly_dispatch.dispatch(
            tcp_view.map(|view| view.header),
            segment.as_ref(),
            timestamp,
            number,
        )?;

        enforce_deadline(&deadline)?;
        sink(FrameRecord {
            number,
            timestamp,
            decoded: &decoded,
            derived_datagrams: &derived,
            scopes: &scopes,
            physical_sources: physical_sources.as_ref(),
            tcp: tcp_view,
            udp: udp_view,
            tcp_events: &tcp_events,
            clock_regression,
        })
        .map_err(|source| Error::Sink { number, source })?;
    }

    enforce_deadline(&deadline)?;
    let (frames_read, bytes_read) = (input.frames(), input.captured_bytes());
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
    let (incomplete_sources, source_outcomes_omitted) = provenance
        .map(crate::analysis::provenance::Tracker::finish)
        .unwrap_or_default();
    Ok(Summary {
        incomplete_sources,
        source_outcomes_omitted,
        frames_read,
        bytes_read,
        frames_matched,
        clock: ip_dispatch.clock_report().clone(),
        trailing_tcp_events: reassembly_dispatch.flush(),
        ip_reassembly: ip_dispatch.report().clone(),
        interfaces: reader.interfaces().to_vec(),
        scopes: scopes.definitions().to_vec(),
    })
}

struct FrameStage<'a> {
    decoder: &'a Dissector,
    deadline: &'a Deadline,
    max_ip_reassembly_bytes: usize,
}

struct PhysicalFrame<'a> {
    decoded: &'a DecodedPacket,
    number: u64,
    timestamp: SystemTime,
}

/// Advances capture-global IP reassembly for one physical frame, returning
/// the derived datagram views its arrival completed, outermost first.
///
/// Every lifecycle event this reveals reaches `ip_sink` before the frame's
/// own record does. The deadline is checked between callbacks; synchronous
/// callbacks must bound their own work because the pipeline cannot interrupt them.
fn advance_ip_reassembly<I>(
    ip_dispatch: &mut IpDispatch,
    stage: &FrameStage<'_>,
    scopes: &mut Interner,
    frame: PhysicalFrame<'_>,
    ip_sink: &mut I,
    provenance: &mut Option<crate::analysis::provenance::Tracker>,
    physical_sources: Option<&crate::analysis::provenance::SourceSet>,
) -> Result<(Vec<DerivedDatagram>, Option<Duration>), Error>
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

    let (now, clock_regression) = ip_dispatch.at(timestamp, number)?;
    let (expired, removed) = ip_dispatch.expire(now);
    emit(expired, ip_sink)?;
    // The scan reconciles tracked keys with datagrams the reassembler
    // dropped; completions release their keys through `Tracker::completed`,
    // so only an expiry sweep that removed something can leave work here.
    if let Some(tracker) = provenance
        && removed
    {
        tracker.retire(|key| ip_dispatch.contains_datagram(key));
    }
    let fragments =
        ip_fragments(decoded, scopes).map_err(|source| Error::Scope { number, source })?;
    if let (Some(tracker), Some(sources)) = (provenance.as_mut(), physical_sources) {
        tracker.remember(&fragments, sources)?;
    }
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
        let sources = provenance
            .as_mut()
            .and_then(|tracker| tracker.completed(&datagram.key));
        let mut next_derived = decode_derived(
            stage.decoder,
            source,
            datagram,
            number,
            budget.max_layers,
            budget.budget_reduced,
            stage.max_ip_reassembly_bytes,
        )?;
        next_derived.sources = sources;
        let next_derived_memory_charge = ip_dispatch
            .charge_derived_memory(derived_memory_charge, budget.charge)
            .map_err(|source| Error::IpReassembly { number, source })?;
        let fragments =
            ip_fragments_in_scope(&next_derived.decoded, source, next_derived.scope, scopes)
                .map_err(|source| Error::Scope { number, source })?;
        if let (Some(tracker), Some(sources)) = (provenance.as_mut(), next_derived.sources.as_ref())
        {
            tracker.remember(&fragments, sources)?;
        }
        let (next_completed, events) = ip_dispatch
            .dispatch(fragments, now, next_derived_memory_charge)
            .map_err(|source| Error::IpReassembly { number, source })?;
        emit(events, ip_sink)?;
        derived.push(next_derived);
        derived_memory_charge = next_derived_memory_charge;
        completed = next_completed;
    }
    Ok((derived, clock_regression))
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

/// Selects the innermost transport of each kind across physical and derived
/// views. A tunneled frame can belong to both UDP and TCP conversations.
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
                    source: IpResource::AggregateMemoryLimit {
                        limit: memory_limit,
                    }
                    .into(),
                }
            } else {
                Error::DerivedDecode { number, source }
            }
        })?;
    Ok(DerivedDatagram {
        sources: None,
        decoded,
        scope,
        fragment_count: datagram.fragment_count,
        unique_bytes: datagram.unique_bytes,
        payload_bytes: datagram.final_payload_length,
        replayed_prefix_layers: replayed_ip_prefix_layers(source),
    })
}

/// Reads one physical frame and charges it against the input
/// [`capture_file::Budget`](crate::capture_file::Budget).
fn next_frame<R: Read>(
    reader: &mut Reader<R>,
    input: &mut crate::capture_file::Budget,
) -> Result<Option<(u64, crate::frame::Frame)>, Error> {
    let number = input.frames().saturating_add(1);
    let Some(frame) = reader
        .next_frame()
        .map_err(|source| Error::Capture { number, source })?
    else {
        return Ok(None);
    };
    input
        .charge(frame.captured_length())
        .map_err(|source| Error::Capture { number, source })?;
    Ok(Some((input.frames(), frame)))
}

fn enforce_deadline(deadline: &Deadline) -> Result<(), Error> {
    deadline.enforce().map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::provenance::{IncompleteSources, SourceFrame, Tracker};
    use crate::analysis::reassembly::ip::OverlapPolicy;
    use crate::build::{Builder, Options as BuildOptions};
    use crate::codec::Context as BuildContext;
    use crate::field::WireValue;
    use crate::layer::Raw;
    use crate::packet::Packet;
    use crate::protocol::builtin;
    use crate::protocol::network::Ipv4;
    use crate::protocol::transport::Udp;
    use std::net::Ipv4Addr;

    fn build(registry: &Arc<Registry>, packet: Packet, seconds: u64) -> Frame {
        let bytes = Builder::new(Arc::clone(registry))
            .build(packet, BuildContext::default(), BuildOptions::default())
            .expect("fixture packet builds")
            .bytes;
        Frame::new(
            SystemTime::UNIX_EPOCH + Duration::from_secs(seconds),
            LinkType::IPV4,
            bytes,
        )
        .expect("fixture frame is valid")
    }

    /// A non-atomic IPv4 fragment: one pending datagram per identification.
    fn fragment_frame(registry: &Arc<Registry>, seconds: u64, identification: u16) -> Frame {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            identification,
            more_fragments: true,
            protocol: WireValue::Exact(17),
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        });
        packet.push(Raw::new(vec![0_u8; 8]));
        build(registry, packet, seconds)
    }

    /// An unfragmented datagram: in scope for provenance but never pending.
    fn datagram_frame(registry: &Arc<Registry>, seconds: u64) -> Frame {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        });
        packet.push(Udp {
            source_port: 50_000,
            destination_port: 9_999,
            ..Udp::default()
        });
        packet.push(Raw::new(vec![1_u8; 8]));
        build(registry, packet, seconds)
    }

    /// The per-frame IP stage of `run`, driven directly so the provenance
    /// tracker stays observable between frames.
    struct Rig {
        decoder: Dissector,
        deadline: Deadline,
        dispatch: IpDispatch,
        scopes: Interner,
        provenance: Option<Tracker>,
        max_frame_bytes: usize,
        max_ip_reassembly_bytes: usize,
    }

    impl Rig {
        fn new() -> Self {
            let limits = Limits::default();
            Self {
                decoder: Dissector::new(builtin::registry()),
                deadline: Deadline::new(limits.max_duration),
                dispatch: IpDispatch::new(limits.ip.clone(), OverlapPolicy::default())
                    .expect("default limits are valid"),
                scopes: Interner::new(),
                provenance: Some(
                    Tracker::new(limits.max_provenance_bytes, limits.ip.max_retained_outcomes)
                        .expect("tracker"),
                ),
                max_frame_bytes: limits.max_frame_bytes,
                max_ip_reassembly_bytes: limits.ip.max_aggregate_bytes,
            }
        }

        fn scans(&self) -> usize {
            self.provenance
                .as_ref()
                .expect("tracker held")
                .retire_scans()
        }

        fn advance(&mut self, frame: Frame, number: u64) {
            let timestamp = frame.timestamp.expect("fixture frames timestamp");
            let decoded = self
                .decoder
                .decode(
                    frame,
                    crate::decode::Options {
                        max_packet_size: self.max_frame_bytes,
                        ..crate::decode::Options::default()
                    },
                )
                .expect("frame decodes");
            let sources = self
                .provenance
                .as_ref()
                .expect("tracker held")
                .single(SourceFrame { number, timestamp })
                .expect("sources");
            let stage = FrameStage {
                decoder: &self.decoder,
                deadline: &self.deadline,
                max_ip_reassembly_bytes: self.max_ip_reassembly_bytes,
            };
            advance_ip_reassembly(
                &mut self.dispatch,
                &stage,
                &mut self.scopes,
                PhysicalFrame {
                    decoded: &decoded,
                    number,
                    timestamp,
                },
                &mut |_| Ok(()),
                &mut self.provenance,
                Some(&sources),
            )
            .expect("frame advances");
        }

        fn finish(&mut self) -> (Vec<IncompleteSources>, u64) {
            self.provenance.take().expect("tracker held").finish()
        }
    }

    fn keyed_sources(incomplete: &[IncompleteSources]) -> Vec<(u16, Vec<u64>)> {
        let mut sources = incomplete
            .iter()
            .map(|entry| {
                let DatagramKey::Ipv4(key) = &entry.key else {
                    panic!("fixture uses IPv4 keys only");
                };
                (
                    key.identification,
                    entry
                        .sources
                        .frames()
                        .iter()
                        .map(|frame| frame.number)
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        sources.sort();
        sources
    }

    #[test]
    fn provenance_reconciliation_waits_for_a_removal() {
        let registry = builtin::registry();
        let mut rig = Rig::new();

        rig.advance(fragment_frame(&registry, 0, 1), 1);
        for number in 2..=6_u64 {
            rig.advance(datagram_frame(&registry, number - 1), number);
        }

        assert_eq!(
            rig.scans(),
            0,
            "no datagram left the reassembler, so no reconciliation ran"
        );

        let (incomplete, omitted) = rig.finish();
        assert_eq!(omitted, 0);
        assert_eq!(
            keyed_sources(&incomplete),
            [(1, vec![1])],
            "the pending datagram retires at end of capture with its source"
        );
    }

    #[test]
    fn expiry_still_retires_tracked_sources() {
        let registry = builtin::registry();
        let mut rig = Rig::new();

        rig.advance(fragment_frame(&registry, 0, 7), 1);
        assert_eq!(rig.scans(), 0);

        // The next frame's sweep expires idle datagram 7, so the scan runs.
        rig.advance(datagram_frame(&registry, 40), 2);
        assert_eq!(rig.scans(), 1);
        assert_eq!(
            rig.dispatch.report().counters.ipv4.idle_expired_datagrams,
            1
        );

        // Frame three retires nothing on its own; its scan is skipped again.
        rig.advance(fragment_frame(&registry, 41, 8), 3);
        assert_eq!(rig.scans(), 1);

        let (incomplete, omitted) = rig.finish();
        assert_eq!(omitted, 0);
        assert_eq!(
            keyed_sources(&incomplete),
            [(7, vec![1]), (8, vec![3])],
            "expiry swept datagram 7; end of capture swept datagram 8"
        );
        assert_eq!(
            rig.dispatch.report().counters.ipv4.end_of_capture_datagrams,
            0,
            "the pipeline flush path is not what retired the datagrams here"
        );
    }
}
