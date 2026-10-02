// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::Error;
use super::super::buffer::union_balanced;
use super::super::model::{Certainty, Header, IssueScope, Status};
use super::super::stream::{CLIENT, SERVER, peer};
use super::{Chain, ChainHead, Conn, Cx, Decoded, Evidence, Fault, Pos, resources};
use crate::protocol::application::http2 as wire;
use crate::protocol::application::http2::hpack;
use bytes::Bytes;
use std::collections::HashSet;

pub(crate) struct DataHead {
    pub(crate) side: usize,
    pub(crate) stream_id: u32,
    pub(crate) length: u32,
    pub(crate) data_bytes: u64,
    pub(crate) end_stream: bool,
}

impl Conn {
    pub(crate) fn frame_step(&mut self, side: usize, cx: &mut Cx<'_>) -> Result<bool, Error> {
        cx.check_deadline()?;
        if self.waiting_settings_ack(side) {
            return Ok(false);
        }
        {
            let dir = self.dirs[side].as_mut().ok_or(Error::Application(
                crate::analysis::application::Error::Sources {
                    number: self.number,
                },
            ))?;
            if dir.buffer.len() < 9 {
                return Ok(false);
            }
            let header = Bytes::copy_from_slice(&dir.buffer.bytes()[..9]);
            if let Err(error) = wire::parse_frame_for_analysis(&header, cx.limits.max_frame_bytes) {
                return self.frame_fault(side, error, cx);
            }
            let length = usize::try_from(u32::from_be_bytes([0, header[0], header[1], header[2]]))
                .expect("24-bit frame length");
            let receiver = &self.settings[peer(side)];
            let effective_max = receiver.permitted_frame_size();
            if length as u32 > effective_max {
                let flow = dir.flow.clone();
                let sets = dir.buffer.contributors(9);
                let (_, dropped) = dir.buffer.take(9);
                let sources = union_balanced(sets)?;
                Self::release_dir(dir, cx, 9);
                Self::release_dropped(dir, dropped, cx);
                self.issue(
                    cx,
                    Fault {
                        flow,
                        http2_stream_id: None,
                        scope: IssueScope::Connection,
                        certainty: Certainty::Confirmed,
                        status: Status::Malformed,
                        code: "frame_over_max_size",
                        detail: format!("frame payload {length} exceeds the permitted maximum")
                            .into(),
                        wire: header,
                        sources,
                    },
                )?;
                self.fail(cx, Status::Malformed)?;
                return Ok(true);
            }
            if dir.buffer.len() < 9 + length {
                return Ok(false);
            }
        }
        let dir = self.dirs[side].as_mut().expect("dir");
        let length = usize::try_from(u32::from_be_bytes([
            0,
            dir.buffer.bytes()[0],
            dir.buffer.bytes()[1],
            dir.buffer.bytes()[2],
        ]))
        .expect("24-bit frame length");
        let total = 9 + length;
        let setting_words = size_of::<wire::Setting>();
        let scratch = total
            .checked_mul(2)
            .and_then(|v| {
                v.checked_add((length / 6).saturating_mul(setting_words.saturating_mul(2)))
            })
            .and_then(|v| {
                v.checked_add(
                    resources::EVENT_OVERHEAD
                        + 4 * size_of::<super::super::settings::SettingIssue>(),
                )
            })
            .ok_or(Error::Application(
                crate::analysis::application::Error::Limit {
                    field: "frame_scratch",
                    limit: total,
                },
            ))?;
        cx.charge_live(scratch)?;
        let result = (|conn: &mut Self, cx: &mut Cx<'_>| -> Result<bool, Error> {
            let dir = conn.dirs[side].as_mut().expect("dir");
            let wire_bytes = Bytes::copy_from_slice(&dir.buffer.bytes()[..total]);
            let parsed = wire::parse_frame_for_analysis(&wire_bytes, cx.limits.max_frame_bytes);
            match parsed {
                Ok(Some((frame, _))) => {
                    cx.check_frames()?;
                    let dir = conn.dirs[side].as_mut().expect("dir");
                    let sets = dir.buffer.contributors(total);
                    let dropped = dir.buffer.discard(total);
                    Self::release_dir(dir, cx, total);
                    Self::release_dropped(dir, dropped, cx);
                    let sources = union_balanced(sets)?;
                    conn.frames += 1;
                    conn.handle_frame(side, frame, wire_bytes, sources, cx)?;
                    Ok(true)
                }
                Ok(None) => Ok(false),
                Err(error) => conn.frame_fault(side, error, cx),
            }
        })(self, cx);
        cx.release_live(scratch);
        result
    }

    fn frame_fault(
        &mut self,
        side: usize,
        error: wire::Error,
        cx: &mut Cx<'_>,
    ) -> Result<bool, Error> {
        let dir = self.dirs[side].as_mut().expect("dir");
        let bytes = dir.buffer.bytes();
        let priority_length_error = matches!(
            error,
            wire::Error::Invalid("frame has an invalid fixed length")
        ) && bytes.len() >= 9
            && bytes[3] == 2;
        let interrupted_chain = priority_length_error && dir.chain.is_some();
        let stream_error = priority_length_error && !interrupted_chain;
        let stream_id = stream_error
            .then(|| u32::from_be_bytes([bytes[5] & 0x7f, bytes[6], bytes[7], bytes[8]]));
        let take = if stream_error {
            let total = 9 + u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize;
            if bytes.len() < total {
                return Ok(false);
            }
            cx.check_frames()?;
            self.frames += 1;
            total
        } else {
            dir.buffer.len()
        };
        let sets = dir.buffer.contributors(take);
        let (wire, dropped) = dir.buffer.take(take);
        let sources = union_balanced(sets)?;
        Self::release_dir(dir, cx, take);
        Self::release_dropped(dir, dropped, cx);
        let flow = dir.flow.clone();
        let (status, code, detail) = match &error {
            _ if interrupted_chain => (
                Status::Malformed,
                "broken_header_block",
                "an invalid PRIORITY frame interrupts an unfinished header block".to_owned(),
            ),
            wire::Error::Limit(limit) => (Status::Limit, "frame_limit", format!("{limit}")),
            wire::Error::Invalid(reason) => {
                (Status::Malformed, "frame_invalid", (*reason).to_string())
            }
            wire::Error::Compression(reason) => {
                (Status::Malformed, "compression", (*reason).to_string())
            }
        };
        self.issue(
            cx,
            Fault {
                flow,
                http2_stream_id: stream_id,
                scope: if stream_error {
                    IssueScope::Stream
                } else {
                    IssueScope::Connection
                },
                certainty: Certainty::Confirmed,
                status,
                code,
                detail: detail.into(),
                wire,
                sources,
            },
        )?;
        if !stream_error {
            self.fail(cx, status)?;
        } else if let Some(id) = stream_id
            && self.streams.contains_key(&id)
        {
            self.close_stream(id, Status::Malformed, None, cx)?;
        }
        Ok(true)
    }

    fn handle_frame(
        &mut self,
        side: usize,
        frame: wire::Frame,
        wire_bytes: Bytes,
        sources: Option<crate::analysis::provenance::SourceSet>,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        let header = frame.header.clone();
        let stream_id = header.stream_id;
        let chained = self.dirs[side]
            .as_ref()
            .and_then(|dir| dir.chain.as_ref().map(|chain| chain.stream_id));
        if let Some(chained) = chained {
            if header.frame_type != 0x9 || stream_id != chained {
                let flow = self.dir_flow(side);
                self.issue(
                    cx,
                    Fault {
                        flow,
                        http2_stream_id: Some(stream_id),
                        scope: IssueScope::Connection,
                        certainty: Certainty::Confirmed,
                        status: Status::Malformed,
                        code: "broken_header_block",
                        detail: "a frame interrupts an unfinished header block".into(),
                        wire: wire_bytes.clone(),
                        sources: sources.clone(),
                    },
                )?;
                self.fail(cx, Status::Malformed)?;
                return Ok(());
            }
        } else if header.frame_type == 0x9 {
            let flow = self.dir_flow(side);
            self.issue(
                cx,
                Fault {
                    flow,
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "stray_continuation",
                    detail: "CONTINUATION does not follow a header block".into(),
                    wire: wire_bytes.clone(),
                    sources: sources.clone(),
                },
            )?;
            self.fail(cx, Status::Malformed)?;
            return Ok(());
        }
        let receiver = &self.settings[peer(side)];
        let effective_max = receiver.permitted_frame_size();
        if header.length > effective_max {
            let flow = self.dir_flow(side);
            self.issue(
                cx,
                Fault {
                    flow,
                    http2_stream_id: (stream_id != 0).then_some(stream_id),
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "frame_over_max_size",
                    detail: format!(
                        "frame payload {} exceeds the permitted maximum",
                        header.length
                    )
                    .into(),
                    wire: wire_bytes.slice(..9),
                    sources: sources.clone(),
                },
            )?;
        } else if header.length
            > receiver
                .advertised
                .max_frame_size
                .min(receiver.acknowledged.max_frame_size)
        {
            let flow = self.dir_flow(side);
            self.issue(
                cx,
                Fault {
                    flow,
                    http2_stream_id: (stream_id != 0).then_some(stream_id),
                    scope: IssueScope::Connection,
                    certainty: Certainty::ObservedOrder,
                    status: Status::Malformed,
                    code: "frame_size_ordering",
                    detail: format!(
                        "frame payload {} exceeds an unacknowledged bound",
                        header.length
                    )
                    .into(),
                    wire: wire_bytes.slice(..9),
                    sources: sources.clone(),
                },
            )?;
        }
        let semantic_error = match &frame.payload {
            wire::Payload::Priority(priority)
            | wire::Payload::Headers {
                priority: Some(priority),
                ..
            } if priority.dependency == stream_id => Some("priority depends on its own stream"),
            wire::Payload::WindowUpdate { increment: 0 } => {
                Some("WINDOW_UPDATE has a zero increment")
            }
            _ => None,
        };
        if let Some(detail) = semantic_error {
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: (stream_id != 0).then_some(stream_id),
                    scope: if stream_id == 0 {
                        IssueScope::Connection
                    } else {
                        IssueScope::Stream
                    },
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "frame_invalid",
                    detail: detail.into(),
                    wire: wire_bytes.clone(),
                    sources: sources.clone(),
                },
            )?;
            if stream_id == 0 {
                self.fail(cx, Status::Malformed)?;
                return Ok(());
            }
        }
        if semantic_error.is_some() && !matches!(frame.payload, wire::Payload::Headers { .. }) {
            // Invalid control values remain in the issue's exact wire evidence,
            // rather than being emitted as a valid typed control payload.
            if self.streams.contains_key(&stream_id) {
                self.close_stream(stream_id, Status::Malformed, None, cx)?;
            }
            return Ok(());
        }
        self.emit_frame(side, &frame, &wire_bytes, sources.clone(), cx)?;
        self.apply_frame(
            side,
            frame,
            Evidence {
                wire: wire_bytes,
                sources,
            },
            cx,
        )
    }

    fn emit_frame(
        &mut self,
        side: usize,
        frame: &wire::Frame,
        wire_bytes: &Bytes,
        sources: Option<crate::analysis::provenance::SourceSet>,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        let (control, payload_wire, data_bytes, padding_bytes) = match &frame.payload {
            wire::Payload::Data { data, padding } => (None, None, data.len() as u64, padding.len()),
            wire::Payload::Headers { padding, .. } | wire::Payload::PushPromise { padding, .. } => {
                (
                    Some(frame.payload.clone()),
                    Some(wire_bytes.slice(9..)),
                    0,
                    padding.len(),
                )
            }
            _ => (
                Some(frame.payload.clone()),
                Some(wire_bytes.slice(9..)),
                0,
                0,
            ),
        };
        let mut header_wire = [0u8; 9];
        header_wire.copy_from_slice(&wire_bytes[..9]);
        let retained = if payload_wire.is_some() {
            wire_bytes.len()
        } else {
            9
        };
        let retained = retained
            + match &control {
                Some(wire::Payload::Settings(values)) => {
                    values.capacity() * size_of::<wire::Setting>()
                }
                _ => 0,
            };
        let sources = sources.ok_or(Error::Application(
            crate::analysis::application::Error::Sources {
                number: self.number,
            },
        ))?;
        cx.charge_retained(
            retained
                + resources::EVENT_OVERHEAD
                + resources::SET_OVERHEAD
                + sources.frames().len() * resources::SPAN_OVERHEAD,
        )?;
        cx.frame(super::super::model::Frame {
            index: self.frames,
            stream: self.stream,
            generation: self.generation,
            flow: self.dir_flow(side),
            header: frame.header.clone(),
            header_wire,
            control,
            payload_wire,
            data_bytes,
            padding_bytes,
            sources,
        });
        Ok(())
    }

    fn apply_frame(
        &mut self,
        side: usize,
        frame: wire::Frame,
        evidence: Evidence,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        let flags = frame.header.flags;
        let stream_id = frame.header.stream_id;
        let first_frame = {
            let Some(dir) = self.dirs[side].as_mut() else {
                return Ok(());
            };
            let first = !dir.saw_frame;
            dir.saw_frame = true;
            first
        };
        if first_frame && !(frame.header.frame_type == 0x4 && flags & 0x1 == 0) {
            let certainty = if side == CLIENT || self.clean_start {
                Certainty::Confirmed
            } else {
                Certainty::Indeterminate
            };
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: None,
                    scope: IssueScope::Connection,
                    certainty,
                    status: Status::Malformed,
                    code: "missing_initial_settings",
                    detail: "the first frame on a direction was not a non-ACK SETTINGS".into(),
                    wire: evidence.wire.slice(..9),
                    sources: evidence.sources.clone(),
                },
            )?;
            if certainty == Certainty::Confirmed {
                self.fail(cx, Status::Malformed)?;
                return Ok(());
            }
        }
        match frame.payload {
            wire::Payload::Data { data, .. } => self.data_frame(
                DataHead {
                    side,
                    stream_id,
                    length: frame.header.length,
                    data_bytes: data.len() as u64,
                    end_stream: flags & 0x1 != 0,
                },
                Evidence {
                    wire: Bytes::copy_from_slice(&evidence.wire[..9]),
                    sources: evidence.sources,
                },
                cx,
            ),
            wire::Payload::Headers {
                fragment, priority, ..
            } => self.block_start(
                Pos { side, stream_id },
                ChainHead::Headers {
                    end_stream: flags & 0x1 != 0,
                    malformed: priority.is_some_and(|priority| priority.dependency == stream_id),
                },
                fragment,
                evidence,
                cx,
                flags & 0x4 != 0,
            ),
            wire::Payload::Reset { .. } => self.reset_stream(side, stream_id, evidence, cx),
            wire::Payload::Settings(settings) => {
                self.settings_frame(side, flags, settings, evidence, cx)
            }
            wire::Payload::PushPromise {
                promised_stream_id,
                fragment,
                ..
            } => self.block_start(
                Pos { side, stream_id },
                ChainHead::PushPromise {
                    promised: promised_stream_id,
                },
                fragment,
                evidence,
                cx,
                flags & 0x4 != 0,
            ),
            wire::Payload::Ping(opaque) => self.ping_frame(side, flags, opaque, evidence, cx),
            wire::Payload::Priority(_) | wire::Payload::Unknown(_) => Ok(()),
            wire::Payload::Goaway { last_stream_id, .. } => {
                self.goaway_frame(side, last_stream_id, evidence, cx)
            }
            wire::Payload::WindowUpdate { increment } => {
                self.window_update(side, stream_id, increment, evidence, cx)
            }
            wire::Payload::Continuation(fragment) => {
                self.block_continue(side, stream_id, fragment, flags, evidence, cx)
            }
        }
    }

    fn data_frame(
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
            .is_some_and(|closed| closed.reset_by == Some(peer(side)))
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
                && !self.early_response_headers.contains(&stream_id)
            {
                self.issue(cx, Fault {
                    flow: self.dir_flow(side), http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream, certainty: Certainty::Confirmed,
                    status: Status::Malformed, code: "data_without_headers",
                    detail: "server DATA preceded any response HEADERS in the same ordered byte stream".into(),
                    wire: evidence.wire, sources: evidence.sources,
                })?;
                cx.check_streams()?;
                self.admitted_streams += 1;
                self.charge_conn(cx, resources::CLOSED_STREAM_OVERHEAD)?;
                self.closed.insert(
                    stream_id,
                    super::ClosedStream {
                        reset_by: None,
                        request: None,
                    },
                );
                return Ok(());
            }
            let uncertain = !closed && (!self.clean_start || side != owner);
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
            } else {
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
        if stream.response_bodyless && side == SERVER && data_bytes > 0 {
            let flow = self.dir_flow(side);
            self.issue(
                cx,
                Fault {
                    flow,
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "bodyless_response_body",
                    detail: "a response that must not carry a body carried DATA".into(),
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

    fn block_start(
        &mut self,
        at: Pos,
        head: ChainHead,
        fragment: Bytes,
        evidence: Evidence,
        cx: &mut Cx<'_>,
        end_headers: bool,
    ) -> Result<(), Error> {
        let Pos { side, stream_id } = at;
        let Evidence { wire, sources } = evidence;
        if fragment.len() > cx.limits.max_header_block_bytes {
            self.limited_block(cx, side, stream_id, wire, sources)?;
            return Ok(());
        }
        let charge = fragment.len() + resources::HEADER_OVERHEAD;
        cx.charge_live(charge)?;
        let mut chain = Chain {
            stream_id,
            head,
            bytes: bytes::BytesMut::from(&fragment[..]),
            frames: 1,
            sets: Vec::new(),
            charged: charge,
            charged_spans: 0,
        };
        if let Some(sources) = sources.clone() {
            if let Err(error) = cx.charge_sources(&sources) {
                cx.release_live(charge);
                return Err(error);
            }
            chain.charged_spans += sources.frames().len();
            chain.charged +=
                resources::SET_OVERHEAD + sources.frames().len() * resources::SPAN_OVERHEAD;
            chain.sets.push(sources);
        }
        if chain.bytes.len() > cx.limits.max_header_block_bytes {
            cx.release_live(chain.charged);
            *cx.spans = cx
                .spans
                .checked_sub(chain.charged_spans)
                .expect("chain spans");
            self.limited_block(cx, side, stream_id, wire, sources)?;
            return Ok(());
        }
        if end_headers {
            self.block_done(side, chain, cx)
        } else {
            let dir = self.dirs[side].as_mut().expect("dir");
            dir.charged += chain.charged;
            dir.charged_spans += chain.charged_spans;
            dir.chain = Some(chain);
            Ok(())
        }
    }

    fn block_continue(
        &mut self,
        side: usize,
        stream_id: u32,
        fragment: Bytes,
        flags: u8,
        evidence: Evidence,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        let Evidence { wire, sources } = evidence;
        let dir = self.dirs[side].as_mut().expect("dir");
        let Some(mut chain) = dir.chain.take() else {
            return Ok(());
        };
        dir.charged -= chain.charged;
        dir.charged_spans -= chain.charged_spans;
        debug_assert_eq!(chain.stream_id, stream_id);
        if chain.bytes.len() + fragment.len() > cx.limits.max_header_block_bytes
            || chain.frames + 1 > cx.limits.max_continuations + 1
        {
            cx.release_live(chain.charged);
            *cx.spans = cx
                .spans
                .checked_sub(chain.charged_spans)
                .expect("chain spans");
            self.limited_block(cx, side, stream_id, wire, sources)?;
            return Ok(());
        }
        if let Err(error) = cx.charge_live(fragment.len()) {
            cx.release_live(chain.charged);
            *cx.spans -= chain.charged_spans;
            return Err(error);
        }
        chain.bytes.extend_from_slice(&fragment);
        chain.charged += fragment.len();
        chain.frames += 1;
        if let Some(sources) = sources.clone() {
            if let Err(error) = cx.charge_sources(&sources) {
                cx.release_live(chain.charged);
                *cx.spans = cx
                    .spans
                    .checked_sub(chain.charged_spans)
                    .expect("chain spans");
                return Err(error);
            }
            chain.charged_spans += sources.frames().len();
            chain.charged +=
                resources::SET_OVERHEAD + sources.frames().len() * resources::SPAN_OVERHEAD;
            chain.sets.push(sources);
        }
        if flags & 0x4 != 0 {
            self.block_done(side, chain, cx)
        } else {
            let dir = self.dirs[side].as_mut().expect("dir");
            dir.charged += chain.charged;
            dir.charged_spans += chain.charged_spans;
            dir.chain = Some(chain);
            Ok(())
        }
    }

    fn limited_block(
        &mut self,
        cx: &mut Cx<'_>,
        side: usize,
        stream_id: u32,
        wire: Bytes,
        sources: Option<crate::analysis::provenance::SourceSet>,
    ) -> Result<(), Error> {
        let flow = self.dir_flow(side);
        self.issue(
            cx,
            Fault {
                flow,
                http2_stream_id: Some(stream_id),
                scope: IssueScope::Connection,
                certainty: Certainty::Confirmed,
                status: Status::Limit,
                code: "block_limit",
                detail: "a header block exceeded its configured bound".into(),
                wire,
                sources,
            },
        )?;
        self.fail(cx, Status::Limit)
    }

    fn block_done(&mut self, side: usize, mut chain: Chain, cx: &mut Cx<'_>) -> Result<(), Error> {
        cx.release_live(chain.charged);
        *cx.spans -= chain.charged_spans;
        cx.check_deadline()?;
        let bytes = chain.bytes.freeze();
        let stream_id = chain.stream_id;
        let origin = self.next_origin;
        self.next_origin += 1;
        let block_sets = std::mem::take(&mut chain.sets);
        let block_sources = union_balanced(block_sets)?;
        let dir = self.dirs[side].as_mut().expect("dir");
        if let Some(sources) = block_sources.clone() {
            Self::track_sources(dir, cx, &sources)?;
            let dir = self.dirs[side].as_mut().expect("dir");
            dir.block_sources.insert(origin, sources);
            Self::charge_dir(dir, cx, resources::ORIGIN_ENTRY_OVERHEAD)?;
        }
        let scratch = 6usize
            .checked_mul(cx.limits.max_header_bytes)
            .and_then(|v| {
                v.checked_add(
                    2usize.saturating_mul(
                        cx.limits
                            .max_headers
                            .saturating_mul(size_of::<hpack::Field>()),
                    ),
                )
            })
            .and_then(|v| v.checked_add(2usize.saturating_mul(cx.limits.max_table_bytes)))
            .and_then(|v| v.checked_add(2usize.saturating_mul(bytes.len())))
            .ok_or(Error::Application(
                crate::analysis::application::Error::Limit {
                    field: "hpack_scratch",
                    limit: cx.limits.max_header_bytes,
                },
            ))?;
        cx.charge_live(scratch)?;
        let result = (|| {
            let updates = hpack::table_size_updates(&bytes, &mut || {
                cx.check_deadline().map_err(hpack::DecodeError::Interrupted)
            });
            let mut ambiguous_minimum = false;
            let decoded = match updates {
                Err(error) => Err(error),
                Ok(updates) => {
                    let (minimum, confirmed_prefix, pending_uncertain) = updates
                        .map_or((None, 0, None), |(_, maximum)| {
                            self.settings[peer(side)].causal_table_minimum(maximum)
                        });
                    let uncertain = [
                        pending_uncertain,
                        self.settings[peer(side)].uncertain_table_minimum,
                    ]
                    .into_iter()
                    .flatten()
                    .min();
                    let decoder = self.dirs[side]
                        .as_mut()
                        .expect("dir")
                        .decoder
                        .as_mut()
                        .expect("decoder");
                    ambiguous_minimum = uncertain.is_some_and(|bound| {
                        decoder.table_maximum() > bound
                            && updates.is_none_or(|(observed, _)| observed > bound)
                    });
                    if let Some(minimum) = minimum {
                        decoder.require_table_minimum(minimum);
                    }
                    let decoded = decoder.decode_checked(&bytes, origin, &mut || {
                        cx.check_deadline().map_err(hpack::DecodeError::Interrupted)
                    });
                    if decoded.is_ok() {
                        self.settings[peer(side)].uncertain_table_minimum = None;
                        if let Some((minimum, _)) = updates {
                            self.settings[peer(side)]
                                .observed_table_updates(minimum, confirmed_prefix);
                        }
                    }
                    decoded
                }
            };
            let decoded = match decoded {
                Ok(block) => Ok(block),
                Err(hpack::DecodeError::Wire(error)) => Err(error),
                Err(hpack::DecodeError::Interrupted(error)) => return Err(error),
            };
            if decoded.is_ok() && ambiguous_minimum {
                self.issue(cx, Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Compression,
                    certainty: Certainty::ObservedOrder,
                    status: Status::Incomplete,
                    code: "hpack_table_size_ordering",
                    detail: "an earlier table shrink may precede or follow receipt of SETTINGS; its required minimum cannot be confirmed".into(),
                    wire: bytes.clone(),
                    sources: block_sources.clone(),
                })?;
            }
            self.decoder_sync(side, cx)?;
            match decoded {
                Err(error) => {
                    let flow = self.dir_flow(side);
                    let (code, status) = match &error {
                        wire::Error::Limit(_) => ("header_block_limit", Status::Limit),
                        _ => ("hpack_decode", Status::Malformed),
                    };
                    self.issue(
                        cx,
                        Fault {
                            flow,
                            http2_stream_id: Some(stream_id),
                            scope: IssueScope::Compression,
                            certainty: Certainty::Confirmed,
                            status,
                            code,
                            detail: error.to_string().into(),
                            wire: bytes,
                            sources: block_sources,
                        },
                    )?;
                    self.fail(cx, status)?;
                    Ok(())
                }
                Ok(block) => {
                    cx.check_deadline()?;
                    let mut compression_sets: Vec<crate::analysis::provenance::SourceSet> =
                        Vec::new();
                    {
                        let dir = self.dirs[side].as_ref().expect("dir");
                        let mut seen = HashSet::new();
                        for field in &block.fields {
                            for origin in &field.origins {
                                cx.check_deadline()?;
                                if !seen.insert(*origin) {
                                    continue;
                                }
                                let Some(set) = dir.block_sources.get(origin) else {
                                    return Err(Error::Application(
                                        crate::analysis::application::Error::Sources {
                                            number: self.number,
                                        },
                                    ));
                                };
                                // Origins are keyed above; the balanced source union
                                // deduplicates overlapping physical frames without an
                                // all-previous-sets comparison for each origin.
                                compression_sets.push(set.clone());
                            }
                        }
                    }
                    let compression = union_balanced(compression_sets)?;
                    let decoded_bytes = block.decoded_bytes;
                    {
                        let dir = self.dirs[side].as_mut().expect("dir");
                        let kept: HashSet<u64> = dir
                            .decoder
                            .as_ref()
                            .expect("decoder")
                            .retained_origins()
                            .into_iter()
                            .collect();
                        let removed: Vec<u64> = dir
                            .block_sources
                            .keys()
                            .filter(|id| !kept.contains(*id))
                            .copied()
                            .collect();
                        for id in removed {
                            if let Some(set) = dir.block_sources.remove(&id) {
                                Self::release_dropped(dir, vec![set], cx);
                                Self::release_dir(dir, cx, resources::ORIGIN_ENTRY_OVERHEAD);
                            }
                        }
                    }
                    if let Some(limit) = self.settings[peer(side)].advertised.max_header_list_size
                        && decoded_bytes > limit as usize
                    {
                        let flow = self.dir_flow(side);
                        self.issue(
                        cx,
                        Fault {
                            flow,
                            http2_stream_id: Some(stream_id),
                            scope: IssueScope::Stream,
                            certainty: Certainty::ObservedOrder,
                            status: Status::Incomplete,
                            code: "header_list_size_advisory",
                            detail: format!(
                                "decoded header list {decoded_bytes} exceeds the peer's advertised maximum"
                            )
                            .into(),
                            wire: Bytes::new(),
                            sources: None,
                        },
                    )?;
                    }
                    let headers: Vec<Header> = block
                        .fields
                        .iter()
                        .map(|field| Header {
                            name: field.name.clone(),
                            value: field.value.clone(),
                            never_indexed: field.never_indexed,
                        })
                        .collect();
                    self.headers_block(
                        side,
                        stream_id,
                        chain.head,
                        Decoded {
                            headers,
                            block: bytes,
                            sources: block_sources,
                            compression,
                        },
                        cx,
                    )
                }
            }
        })();
        cx.release_live(scratch);
        result
    }
}
