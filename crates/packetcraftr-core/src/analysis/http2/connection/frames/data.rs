// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DATA payload validation, stream flow control, and message body retention.

use super::super::{ConnectionState, Context, Evidence, Fault};
use crate::analysis::http2::Error;
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::budget;
use crate::analysis::http2::model::{Certainty, IssueScope, Status};
use crate::analysis::http2::side::Side;

pub(super) struct DataHead {
    pub(super) side: Side,
    pub(super) stream_id: u32,
    pub(super) length: u32,
    pub(super) data_bytes: u64,
    pub(super) end_stream: bool,
}

impl ConnectionState {
    pub(super) fn data_frame(
        &mut self,
        head: DataHead,
        evidence: Evidence,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let DataHead {
            side,
            stream_id,
            length,
            data_bytes,
            end_stream,
        } = head;
        self.control.send_window[side] = self.control.send_window[side]
            .checked_sub(i64::from(length))
            .ok_or(Error::Application(
                crate::analysis::application::Error::Limit {
                    field: "flow_window",
                    limit: 0x8000_0000,
                },
            ))?;
        if self.control.send_window[side] < -(1i64 << 31) {
            let flow = self.dir_flow(side);
            self.reject(
                context,
                Fault::new(
                    flow,
                    IssueScope::Connection,
                    Status::Malformed,
                    IssueCode::ConnectionWindowUnderflow,
                    "connection flow window passed the 31-bit floor",
                )
                .stream(Some(stream_id))
                .evidence(evidence.wire.clone(), evidence.sources.clone()),
            )?;
            return Ok(());
        } else if length > 0 && self.control.send_window[side] < 0 {
            let flow = self.dir_flow(side);
            self.issue(
                context,
                Fault::new(
                    flow,
                    IssueScope::Connection,
                    Status::Malformed,
                    IssueCode::ConnectionWindowExceeded,
                    "DATA exceeded the observed connection window",
                )
                .stream(Some(stream_id))
                .certainty(Certainty::ObservedOrder)
                .evidence(evidence.wire.clone(), evidence.sources.clone()),
            )?;
        }
        if self.control.send_window[side] < 0
            && self.reconcile_closed_credit(side, Some(stream_id), context)?
        {
            return Ok(());
        }
        // In-flight peer DATA after a reset still consumes connection credit,
        // but cannot establish a stream error from cross-direction ordering.
        if self
            .streams
            .closed
            .get(&stream_id)
            .is_some_and(|closed| closed.reset_by == Some(side.peer()) && !closed.ended[side])
        {
            return Ok(());
        }
        let Some(stream) = self.streams.open.get_mut(&stream_id) else {
            let owner = Side::initiator_of(stream_id);
            let closed = self.streams.closed.contains_key(&stream_id)
                || stream_id <= self.streams.max_initiated[owner];
            if !closed
                && self.clean_start
                && side == Side::Server
                && owner == Side::Client
                && self
                    .streams
                    .early_responses
                    .get(&stream_id)
                    .is_none_or(|early| !early.final_seen || early.ended)
            {
                self.issue(
                    context,
                    Fault::new(
                        self.dir_flow(side),
                        IssueScope::Stream,
                        Status::Malformed,
                        IssueCode::DataWithoutHeaders,
                        "server DATA preceded any response HEADERS in the same ordered byte stream",
                    )
                    .stream(Some(stream_id))
                    .evidence(evidence.wire, evidence.sources),
                )?;
                if !self.streams.early_responses.contains_key(&stream_id) {
                    context.check_streams()?;
                    self.streams.admitted += 1;
                    context.charge(&mut self.charge, budget::CLOSED_STREAM_OVERHEAD)?;
                }
                self.streams
                    .early_responses
                    .entry(stream_id)
                    .or_default()
                    .ended = true;
                return Ok(());
            }
            // A capture-early final response that cannot carry content is
            // contradicted by content in the server's own ordered bytes.
            if !closed
                && self.clean_start
                && side == Side::Server
                && owner == Side::Client
                && data_bytes > 0
                && let Some(early) = self.streams.early_responses.get_mut(&stream_id)
                && early.final_seen
                && early.bodyless
                && !early.ended
            {
                early.ended = true;
                self.issue(
                    context,
                    Fault::new(
                        self.dir_flow(side),
                        IssueScope::Stream,
                        Status::Malformed,
                        IssueCode::BodylessResponseBody,
                        "a capture-delayed response that must not carry content carried DATA",
                    )
                    .stream(Some(stream_id))
                    .evidence(evidence.wire, evidence.sources),
                )?;
                return Ok(());
            }
            let uncertain = !closed && (!self.clean_start || side != owner);
            if side == Side::Server
                && end_stream
                && let Some(early) = self.streams.early_responses.get_mut(&stream_id)
            {
                early.ended = true;
            }
            let flow = self.dir_flow(side);
            self.issue(
                context,
                Fault::new(
                    flow,
                    if closed {
                        IssueScope::Stream
                    } else {
                        IssueScope::Connection
                    },
                    if uncertain {
                        Status::Incomplete
                    } else {
                        Status::Malformed
                    },
                    if closed {
                        IssueCode::DataClosedStream
                    } else {
                        IssueCode::DataUnknownStream
                    },
                    if closed {
                        "DATA arrived on a fully closed stream"
                    } else {
                        "DATA arrived on a stream that was never opened"
                    },
                )
                .stream(Some(stream_id))
                .certainty(if uncertain {
                    Certainty::Indeterminate
                } else {
                    Certainty::Confirmed
                })
                .evidence(evidence.wire, evidence.sources),
            )?;
            if !closed && !uncertain {
                self.fail(context, Status::Malformed)?;
            }
            return Ok(());
        };
        if stream.phase != crate::analysis::http2::stream::Phase::Open || stream.ended[side] {
            let reserved = stream.phase == crate::analysis::http2::stream::Phase::Reserved;
            let preserve_delayed_request = side == Side::Server && stream.early_response.is_some();
            let flow = self.dir_flow(side);
            self.issue(
                context,
                Fault::new(
                    flow,
                    if reserved {
                        IssueScope::Connection
                    } else {
                        IssueScope::Stream
                    },
                    Status::Malformed,
                    IssueCode::DataClosedStream,
                    "DATA arrived on a stream closed to the sender",
                )
                .stream(Some(stream_id))
                .evidence(evidence.wire, evidence.sources),
            )?;
            if reserved {
                self.fail(context, Status::Malformed)?;
            } else if !preserve_delayed_request {
                self.close_stream(stream_id, Status::Malformed, None, context)?;
            }
            return Ok(());
        }
        stream.send_window[side] -= i64::from(length);
        if length > 0 {
            stream.credit_exceeded[side] = stream.send_window[side] < 0;
        }
        if stream.send_window[side] < -(1i64 << 31) {
            let flow = self.dir_flow(side);
            self.issue(
                context,
                Fault::new(
                    flow,
                    IssueScope::Stream,
                    Status::Malformed,
                    IssueCode::StreamWindowUnderflow,
                    "stream flow window passed the 31-bit floor",
                )
                .stream(Some(stream_id))
                .evidence(evidence.wire.clone(), evidence.sources.clone()),
            )?;
            self.close_stream(stream_id, Status::Malformed, None, context)?;
            return Ok(());
        } else if length > 0 && stream.send_window[side] < 0 {
            let flow = self.dir_flow(side);
            self.issue(
                context,
                Fault::new(
                    flow,
                    IssueScope::Stream,
                    Status::Malformed,
                    IssueCode::StreamWindowExceeded,
                    "DATA exceeded the observed stream window",
                )
                .stream(Some(stream_id))
                .certainty(Certainty::ObservedOrder)
                .evidence(evidence.wire.clone(), evidence.sources.clone()),
            )?;
        }
        if self.reconcile_closed_credit(side, Some(stream_id), context)? {
            return Ok(());
        }
        let stream = self
            .streams
            .open
            .get_mut(&stream_id)
            .ok_or(Error::Invariant("stream"))?;
        let trace_content = side == Side::Client && stream.method.as_deref() == Some(b"TRACE");
        if data_bytes > 0 && (trace_content || (stream.response_bodyless && side == Side::Server)) {
            let flow = self.dir_flow(side);
            self.issue(
                context,
                Fault::new(
                    flow,
                    IssueScope::Stream,
                    Status::Malformed,
                    if trace_content {
                        IssueCode::TraceRequestBody
                    } else {
                        IssueCode::BodylessResponseBody
                    },
                    "a message that must not carry content carried DATA",
                )
                .stream(Some(stream_id))
                .evidence(evidence.wire.clone(), evidence.sources.clone()),
            )?;
            let stream = self
                .streams
                .open
                .get_mut(&stream_id)
                .ok_or(Error::Invariant("stream"))?;
            if let Some(msg) = stream.msgs[side].as_mut() {
                msg.failure = Some(Status::Malformed);
            }
        }
        let stream = self
            .streams
            .open
            .get_mut(&stream_id)
            .ok_or(Error::Invariant("stream"))?;
        if stream.msgs[side]
            .as_ref()
            .is_some_and(|msg| msg.trailers_seen)
        {
            let flow = self.dir_flow(side);
            self.issue(
                context,
                Fault::new(
                    flow,
                    IssueScope::Stream,
                    Status::Malformed,
                    IssueCode::DataAfterTrailers,
                    "DATA arrived after a trailer block",
                )
                .stream(Some(stream_id))
                .evidence(evidence.wire.clone(), evidence.sources.clone()),
            )?;
            let stream = self
                .streams
                .open
                .get_mut(&stream_id)
                .ok_or(Error::Invariant("stream"))?;
            if let Some(msg) = stream.msgs[side].as_mut() {
                msg.failure = Some(Status::Malformed);
            }
        }
        let stream = self
            .streams
            .open
            .get_mut(&stream_id)
            .ok_or(Error::Invariant("stream"))?;
        if let Some(msg) = stream.msgs[side].as_mut() {
            msg.saw_body = true;
            msg.body_bytes = msg.body_bytes.saturating_add(data_bytes);
            if msg.body_bytes > context.limits.max_body_bytes {
                let flow = self.dir_flow(side);
                self.reject(
                    context,
                    Fault::new(
                        flow,
                        IssueScope::Stream,
                        Status::Limit,
                        IssueCode::BodyLimit,
                        "observed message body exceeds the configured bound",
                    )
                    .stream(Some(stream_id))
                    .evidence(evidence.wire.clone(), evidence.sources.clone()),
                )?;
                return Ok(());
            }
            if let Some(sources) = evidence.sources.clone() {
                let stream = self
                    .streams
                    .open
                    .get_mut(&stream_id)
                    .ok_or(Error::Invariant("stream"))?;
                match stream.msgs[side].as_mut() {
                    Some(msg) => {
                        context.track(&mut msg.charge, &sources)?;
                        msg.sets.push(sources);
                    }
                    None => context.charge(
                        &mut self.charge,
                        budget::SET_OVERHEAD + sources.frames().len() * budget::SPAN_OVERHEAD,
                    )?,
                }
            }
        } else if side == Side::Server
            && stream.early_response.is_some_and(|early| early.final_seen)
        {
            self.issue(
                context,
                Fault::new(
                    self.dir_flow(side),
                    IssueScope::Stream,
                    Status::Incomplete,
                    IssueCode::DataAfterEarlyResponse,
                    "DATA follows response HEADERS observed before the delayed client opener",
                )
                .stream(Some(stream_id))
                .certainty(Certainty::Indeterminate)
                .evidence(evidence.wire, evidence.sources),
            )?;
        } else {
            let flow = self.dir_flow(side);
            self.issue(
                context,
                Fault::new(
                    flow,
                    IssueScope::Stream,
                    Status::Malformed,
                    IssueCode::DataWithoutHeaders,
                    "DATA arrived before a header block on the stream",
                )
                .stream(Some(stream_id))
                .evidence(evidence.wire, evidence.sources),
            )?;
            self.close_stream(stream_id, Status::Malformed, None, context)?;
            return Ok(());
        }
        if self
            .streams
            .open
            .get(&stream_id)
            .and_then(|stream| stream.msgs[side].as_ref())
            .is_some_and(|msg| msg.failure == Some(Status::Malformed))
        {
            self.close_stream(stream_id, Status::Malformed, None, context)?;
        } else if end_stream {
            self.end_side(side, stream_id, Status::Complete, context)?;
        }
        Ok(())
    }
}
