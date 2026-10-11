// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DATA payload validation, stream flow control, and message body retention.

use super::super::{Conn, Cx, Evidence, Fault, resources};
use crate::analysis::http2::Error;
use crate::analysis::http2::model::{Certainty, IssueScope, Status};
use crate::analysis::http2::stream::{CLIENT, SERVER, peer};

pub(super) struct DataHead {
    pub(super) side: usize,
    pub(super) stream_id: u32,
    pub(super) length: u32,
    pub(super) data_bytes: u64,
    pub(super) end_stream: bool,
}

impl Conn {
    pub(super) fn data_frame(
        &mut self,
        head: DataHead,
        evidence: Evidence,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        let DataHead {
            side,
            stream_id,
            length,
            data_bytes,
            end_stream,
        } = head;
        self.send_window[side] = self.send_window[side]
            .checked_sub(i64::from(length))
            .ok_or(Error::Application(
                crate::analysis::application::Error::Limit {
                    field: "flow_window",
                    limit: 0x8000_0000,
                },
            ))?;
        if self.send_window[side] < -(1i64 << 31) {
            let flow = self.dir_flow(side);
            self.issue(
                cx,
                Fault {
                    flow,
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "connection_window_underflow",
                    detail: "connection flow window passed the 31-bit floor".into(),
                    wire: evidence.wire.clone(),
                    sources: evidence.sources.clone(),
                },
            )?;
            self.fail(cx, Status::Malformed)?;
            return Ok(());
        } else if length > 0 && self.send_window[side] < 0 {
            let flow = self.dir_flow(side);
            self.issue(
                cx,
                Fault {
                    flow,
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Connection,
                    certainty: Certainty::ObservedOrder,
                    status: Status::Malformed,
                    code: "connection_window_exceeded",
                    detail: "DATA exceeded the observed connection window".into(),
                    wire: evidence.wire.clone(),
                    sources: evidence.sources.clone(),
                },
            )?;
        }
        if self.send_window[side] < 0 && self.reconcile_closed_credit(side, Some(stream_id), cx)? {
            return Ok(());
        }
        // In-flight peer DATA after a reset still consumes connection credit,
        // but cannot establish a stream error from cross-direction ordering.
        if self
            .closed
            .get(&stream_id)
            .is_some_and(|closed| closed.reset_by == Some(peer(side)) && !closed.ended[side])
        {
            return Ok(());
        }
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            let owner = if stream_id.is_multiple_of(2) {
                SERVER
            } else {
                CLIENT
            };
            let closed =
                self.closed.contains_key(&stream_id) || stream_id <= self.max_initiated[owner];
            if !closed
                && self.clean_start
                && side == SERVER
                && owner == CLIENT
                && self
                    .early_response_headers
                    .get(&stream_id)
                    .is_none_or(|early| !early.final_seen || early.ended)
            {
                self.issue(cx, Fault {
                    flow: self.dir_flow(side), http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream, certainty: Certainty::Confirmed,
                    status: Status::Malformed, code: "data_without_headers",
                    detail: "server DATA preceded any response HEADERS in the same ordered byte stream".into(),
                    wire: evidence.wire, sources: evidence.sources,
                })?;
                if !self.early_response_headers.contains_key(&stream_id) {
                    cx.check_streams()?;
                    self.admitted_streams += 1;
                    self.charge_conn(cx, resources::CLOSED_STREAM_OVERHEAD)?;
                }
                self.early_response_headers
                    .entry(stream_id)
                    .or_default()
                    .ended = true;
                return Ok(());
            }
            // A capture-early final response that cannot carry content is
            // contradicted by content in the server's own ordered bytes.
            if !closed
                && self.clean_start
                && side == SERVER
                && owner == CLIENT
                && data_bytes > 0
                && let Some(early) = self.early_response_headers.get_mut(&stream_id)
                && early.final_seen
                && early.bodyless
                && !early.ended
            {
                early.ended = true;
                self.issue(
                    cx,
                    Fault {
                        flow: self.dir_flow(side),
                        http2_stream_id: Some(stream_id),
                        scope: IssueScope::Stream,
                        certainty: Certainty::Confirmed,
                        status: Status::Malformed,
                        code: "bodyless_response_body",
                        detail:
                            "a capture-delayed response that must not carry content carried DATA"
                                .into(),
                        wire: evidence.wire,
                        sources: evidence.sources,
                    },
                )?;
                return Ok(());
            }
            let uncertain = !closed && (!self.clean_start || side != owner);
            if side == SERVER
                && end_stream
                && let Some(early) = self.early_response_headers.get_mut(&stream_id)
            {
                early.ended = true;
            }
            let flow = self.dir_flow(side);
            self.issue(
                cx,
                Fault {
                    flow,
                    http2_stream_id: Some(stream_id),
                    scope: if closed {
                        IssueScope::Stream
                    } else {
                        IssueScope::Connection
                    },
                    certainty: if uncertain {
                        Certainty::Indeterminate
                    } else {
                        Certainty::Confirmed
                    },
                    status: if uncertain {
                        Status::Incomplete
                    } else {
                        Status::Malformed
                    },
                    code: if closed {
                        "data_closed_stream"
                    } else {
                        "data_unknown_stream"
                    },
                    detail: if closed {
                        "DATA arrived on a fully closed stream".into()
                    } else {
                        "DATA arrived on a stream that was never opened".into()
                    },
                    wire: evidence.wire,
                    sources: evidence.sources,
                },
            )?;
            if !closed && !uncertain {
                self.fail(cx, Status::Malformed)?;
            }
            return Ok(());
        };
        if stream.phase != crate::analysis::http2::stream::Phase::Open || stream.ended[side] {
            let reserved = stream.phase == crate::analysis::http2::stream::Phase::Reserved;
            let preserve_delayed_request = side == SERVER && stream.early_response.is_some();
            let flow = self.dir_flow(side);
            self.issue(
                cx,
                Fault {
                    flow,
                    http2_stream_id: Some(stream_id),
                    scope: if reserved {
                        IssueScope::Connection
                    } else {
                        IssueScope::Stream
                    },
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "data_closed_stream",
                    detail: "DATA arrived on a stream closed to the sender".into(),
                    wire: evidence.wire,
                    sources: evidence.sources,
                },
            )?;
            if reserved {
                self.fail(cx, Status::Malformed)?;
            } else if !preserve_delayed_request {
                self.close_stream(stream_id, Status::Malformed, None, cx)?;
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
                cx,
                Fault {
                    flow,
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "stream_window_underflow",
                    detail: "stream flow window passed the 31-bit floor".into(),
                    wire: evidence.wire.clone(),
                    sources: evidence.sources.clone(),
                },
            )?;
            self.close_stream(stream_id, Status::Malformed, None, cx)?;
            return Ok(());
        } else if length > 0 && stream.send_window[side] < 0 {
            let flow = self.dir_flow(side);
            self.issue(
                cx,
                Fault {
                    flow,
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::ObservedOrder,
                    status: Status::Malformed,
                    code: "stream_window_exceeded",
                    detail: "DATA exceeded the observed stream window".into(),
                    wire: evidence.wire.clone(),
                    sources: evidence.sources.clone(),
                },
            )?;
        }
        if self.reconcile_closed_credit(side, Some(stream_id), cx)? {
            return Ok(());
        }
        let stream = self.streams.get_mut(&stream_id).expect("stream");
        let trace_content = side == CLIENT && stream.method.as_deref() == Some(b"TRACE");
        if data_bytes > 0 && (trace_content || (stream.response_bodyless && side == SERVER)) {
            let flow = self.dir_flow(side);
            self.issue(
                cx,
                Fault {
                    flow,
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: if trace_content {
                        "trace_request_body"
                    } else {
                        "bodyless_response_body"
                    },
                    detail: "a message that must not carry content carried DATA".into(),
                    wire: evidence.wire.clone(),
                    sources: evidence.sources.clone(),
                },
            )?;
            let stream = self.streams.get_mut(&stream_id).expect("stream");
            if let Some(msg) = stream.msgs[side].as_mut() {
                msg.failure = Some(Status::Malformed);
            }
        }
        let stream = self.streams.get_mut(&stream_id).expect("stream");
        if stream.msgs[side]
            .as_ref()
            .is_some_and(|msg| msg.trailers_seen)
        {
            let flow = self.dir_flow(side);
            self.issue(
                cx,
                Fault {
                    flow,
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "data_after_trailers",
                    detail: "DATA arrived after a trailer block".into(),
                    wire: evidence.wire.clone(),
                    sources: evidence.sources.clone(),
                },
            )?;
            let stream = self.streams.get_mut(&stream_id).expect("stream");
            if let Some(msg) = stream.msgs[side].as_mut() {
                msg.failure = Some(Status::Malformed);
            }
        }
        let stream = self.streams.get_mut(&stream_id).expect("stream");
        if let Some(msg) = stream.msgs[side].as_mut() {
            msg.saw_body = true;
            msg.body_bytes = msg.body_bytes.saturating_add(data_bytes);
            if msg.body_bytes > cx.limits.max_body_bytes {
                let flow = self.dir_flow(side);
                self.issue(
                    cx,
                    Fault {
                        flow,
                        http2_stream_id: Some(stream_id),
                        scope: IssueScope::Stream,
                        certainty: Certainty::Confirmed,
                        status: Status::Limit,
                        code: "body_limit",
                        detail: "observed message body exceeds the configured bound".into(),
                        wire: evidence.wire.clone(),
                        sources: evidence.sources.clone(),
                    },
                )?;
                self.fail(cx, Status::Limit)?;
                return Ok(());
            }
            if let Some(sources) = evidence.sources.clone() {
                let charge =
                    resources::SET_OVERHEAD + sources.frames().len() * resources::SPAN_OVERHEAD;
                self.charge_conn(cx, charge)?;
                let stream = self.streams.get_mut(&stream_id).expect("stream");
                if let Some(msg) = stream.msgs[side].as_mut() {
                    msg.charged += charge;
                    msg.charged_spans += sources.frames().len();
                    cx.charge_spans(sources.frames().len())?;
                    msg.sets.push(sources);
                }
            }
        } else if side == SERVER && stream.early_response.is_some_and(|early| early.final_seen) {
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::Indeterminate,
                    status: Status::Incomplete,
                    code: "data_after_early_response",
                    detail:
                        "DATA follows response HEADERS observed before the delayed client opener"
                            .into(),
                    wire: evidence.wire,
                    sources: evidence.sources,
                },
            )?;
        } else {
            let flow = self.dir_flow(side);
            self.issue(
                cx,
                Fault {
                    flow,
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "data_without_headers",
                    detail: "DATA arrived before a header block on the stream".into(),
                    wire: evidence.wire,
                    sources: evidence.sources,
                },
            )?;
            self.close_stream(stream_id, Status::Malformed, None, cx)?;
            return Ok(());
        }
        if self
            .streams
            .get(&stream_id)
            .and_then(|stream| stream.msgs[side].as_ref())
            .is_some_and(|msg| msg.failure == Some(Status::Malformed))
        {
            self.close_stream(stream_id, Status::Malformed, None, cx)?;
        } else if end_stream {
            self.end_side(side, stream_id, Status::Complete, cx)?;
        }
        Ok(())
    }
}
