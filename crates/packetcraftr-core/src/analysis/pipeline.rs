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
use crate::registry::Registry;

use crate::analysis::adapter::{
    ScopeBase, TcpTransport, UdpTransport, ip_fragments, replayed_ip_prefix_layers, tcp_segment,
    transports, udp_flow,
};
use crate::analysis::conversation_index::StreamIndex;
use crate::analysis::reassembly::ip::{CompletedDatagram, DatagramKey};
use crate::analysis::reassembly::tcp::Event as TcpEvent;
use crate::analysis::scope::{Interner, Limits as ScopeLimits, MAX_SCOPES};
use crate::analysis::{Error, StreamTransport};
use crate::frame::{Frame, LinkType};

mod clock;
mod dispatch;
mod ip;
mod limits;
mod options;
mod record;

pub use clock::ClockReport;
pub use ip::{
    IpCounters, IpDatagramOutcome, IpEvent, IpEventRecord, IpFamilyCounters, IpReassemblyReport,
};
pub use limits::Limits;
pub use options::{Options, Plan};
pub use record::{Conversation, DerivedDatagram, FrameRecord, TcpView, UdpView};

use dispatch::ReassemblyDispatch;
use ip::IpDispatch;

#[derive(Clone, Debug, Default)]
pub struct Summary {
    pub incomplete_sources: Vec<crate::analysis::provenance::IncompleteSources>,
    pub source_outcomes_omitted: u64,
    pub clock: ClockReport,
    pub frames_read: u64,
    pub bytes_read: u64,
    pub frames_matched: u64,
    pub trailing_tcp_events: Vec<TcpEvent>,
    pub ip_reassembly: IpReassemblyReport,
    pub interfaces: Vec<crate::capture_file::Interface>,
    pub scopes: Vec<crate::analysis::scope::Definition>,
}

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
    // TCP and one UDP analysis scope.
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
                    limits: crate::packet::Limits {
                        max_packet_size: limits.max_frame_bytes,
                        ..crate::packet::Limits::default()
                    },
                },
            )
            .map_err(|source| Error::Decode { number, source })?;

        // Every physical frame advances capture-global IP state before any
        // transport indexing or display filter.
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

        // Assign stream IDs before filtering to keep them stable across runs.
        let segment = match tcp.filter(|_| options.plan.tcp_index || options.tcp_events) {
            Some(elected) => tcp_segment(
                elected.decoded,
                elected.transport,
                elected.base,
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
                elected.base,
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
        let mut record = FrameRecord {
            number,
            timestamp,
            decoded: &decoded,
            derived_datagrams: &derived,
            scopes: &scopes,
            physical_sources: physical_sources.as_ref(),
            tcp: tcp_view,
            udp: udp_view,
            tcp_events: &[],
            clock_regression,
        };
        if let Some(bounds) = options.time_bounds
            && !bounds.contains(Some(timestamp))
        {
            continue;
        }
        if let Some(selected) = options.stream {
            let conversation = match selected.transport {
                StreamTransport::Tcp => record.tcp.and_then(|view| view.conversation),
                StreamTransport::Udp => record.udp.and_then(|view| view.conversation),
            };
            if conversation.is_none_or(|stream| stream.index != selected.index) {
                continue;
            }
        }
        if let Some(filter) = options.filter
            && !record
                .matches(filter)
                .map_err(|source| Error::Filter { number, source })?
        {
            continue;
        }
        frames_matched = frames_matched.saturating_add(1);

        let tcp_events = reassembly_dispatch.dispatch(
            record.tcp.map(|view| view.header),
            segment.as_ref(),
            timestamp,
            number,
        )?;

        enforce_deadline(&deadline)?;
        record.tcp_events = &tcp_events;
        sink(record).map_err(|source| Error::Sink { number, source })?;
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
}

struct PhysicalFrame<'a> {
    decoded: &'a DecodedPacket,
    number: u64,
    timestamp: SystemTime,
}

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
    if let Some(tracker) = provenance
        && removed
    {
        tracker.retire(|key| ip_dispatch.contains_datagram(key));
    }
    let fragments =
        ip_fragments(decoded, None, scopes).map_err(|source| Error::Scope { number, source })?;
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
            ip_dispatch,
        )?;
        next_derived.sources = sources;
        let next_derived_memory_charge = ip_dispatch
            .charge_derived_memory(derived_memory_charge, budget.charge)
            .map_err(|source| Error::IpReassembly { number, source })?;
        let fragments = ip_fragments(
            &next_derived.decoded,
            Some((source, next_derived.scope)),
            scopes,
        )
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

struct ElectedTransport<'a, T> {
    base: ScopeBase<'a>,
    decoded: &'a DecodedPacket,
    transport: T,
}

struct TransportViews<'a> {
    tcp: Option<ElectedTransport<'a, TcpTransport<'a>>>,
    udp: Option<ElectedTransport<'a, UdpTransport>>,
}

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
        .map(|datagram| (Some(datagram.scope), &datagram.decoded));
    let mut previous = decoded;
    for (scope, view) in physical.chain(cascade) {
        let base = scope.map(|scope| (previous, scope));
        let found = transports(&view.packet);
        if let Some(transport) = found.tcp {
            views.tcp = Some(ElectedTransport {
                base,
                decoded: view,
                transport,
            });
        }
        if let Some(transport) = found.udp {
            views.udp = Some(ElectedTransport {
                base,
                decoded: view,
                transport,
            });
        }
        previous = view;
    }
    views
}

fn decode_derived(
    decoder: &Dissector,
    source: &DecodedPacket,
    datagram: CompletedDatagram,
    number: u64,
    max_layers: usize,
    budget_reduced: bool,
    ip_dispatch: &IpDispatch,
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
                limits: crate::packet::Limits {
                    max_layers,
                    max_packet_size: datagram.bytes.len(),
                },
            },
        )
        .map_err(|source| {
            if budget_reduced
                && matches!(&source, crate::decode::Error::LayerLimit { limit } if *limit == max_layers)
            {
                Error::IpReassembly {
                    number,
                    source: ip_dispatch.aggregate_memory_error(),
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
