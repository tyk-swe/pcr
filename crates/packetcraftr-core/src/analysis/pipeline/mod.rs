// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The bounded read → dissect → index → filter → dispatch loop shared by the
//! offline analysis commands.

use std::io::Read;
use std::sync::Arc;

use crate::analysis::pcap::{Error as CaptureError, Reader};
use crate::budget::Deadline;
use crate::decode::{DecodedPacket, Dissector};
use crate::filter::Context as FilterContext;
use crate::registry::Registry;

use crate::analysis::Error;
use crate::analysis::adapter::{tcp_segment, udp_flow};
use crate::analysis::conversation_index::StreamIndex;
use crate::analysis::reassembly::tcp::{Event as TcpEvent, ScopedFlowKey};
use crate::analysis::scope::Interner;

mod clock;
mod dispatch;
mod limits;

pub use limits::{Limits, Options};

use clock::CaptureClock;
use dispatch::ReassemblyDispatch;

/// One matched frame, dispatched in capture order.
#[derive(Debug)]
pub struct FrameRecord<'a> {
    /// 1-based position in the capture, counting unmatched frames too, so
    /// numbers agree with every other command reading the same file.
    pub number: u64,
    pub decoded: &'a DecodedPacket,
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
}

/// Terminal counters and residue for a completed analysis run.
#[derive(Clone, Debug)]
pub struct Summary {
    pub frames_read: u64,
    pub frames_matched: u64,
    /// Data still buffered when the capture ended, flushed flow by flow.
    /// Streams that never saw FIN or RST surface their bytes here.
    pub trailing_tcp_events: Vec<TcpEvent>,
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
    registry: Arc<Registry>,
    options: &Options<'_>,
    mut sink: F,
) -> Result<Summary, Error>
where
    R: Read,
    F: FnMut(FrameRecord<'_>) -> Result<(), crate::error::BoundaryError>,
{
    options.limits.validate()?;
    let limits = &options.limits;
    let deadline = Deadline::new(limits.max_duration);
    let decoder = Dissector::new(registry);
    let mut tcp_streams = StreamIndex::default();
    let mut udp_streams = StreamIndex::default();
    let mut scopes = Interner::new();
    let mut reassembly_dispatch = ReassemblyDispatch::new(options.tcp_events, limits.max_flows);
    let mut clock = CaptureClock::new();

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

        // Assign stream IDs before filtering to keep them stable across runs.
        let segment =
            tcp_segment(&decoded, &mut scopes).map_err(|source| Error::Scope { number, source })?;
        let tcp_stream = match &segment {
            Some(segment) => Some(tcp_streams.assign(&segment.flow, number, limits.max_flows)?),
            None => None,
        };
        let udp_flow =
            udp_flow(&decoded, &mut scopes).map_err(|source| Error::Scope { number, source })?;
        let udp_stream = match &udp_flow {
            Some(flow) => Some(udp_streams.assign(flow, number, limits.max_flows)?),
            None => None,
        };

        if let Some(filter) = options.filter
            && !filter
                .matches(&FilterContext {
                    decoded: &decoded,
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
            &decoded,
            segment.as_ref(),
            timestamp,
            number,
            &mut clock,
            limits.max_flows,
        )?;

        enforce_deadline(&deadline, limits)?;
        sink(FrameRecord {
            number,
            decoded: &decoded,
            tcp_stream,
            tcp_flow: segment.as_ref().map(|segment| &segment.flow),
            udp_stream,
            udp_flow: udp_flow.as_ref(),
            tcp_events: &tcp_events,
        })
        .map_err(|source| Error::Sink { number, source })?;
    }

    enforce_deadline(&deadline, limits)?;
    Ok(Summary {
        frames_read,
        frames_matched,
        trailing_tcp_events: reassembly_dispatch.flush(),
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
