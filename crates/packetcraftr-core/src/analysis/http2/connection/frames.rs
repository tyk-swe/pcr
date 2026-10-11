// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod data;
mod headers;

use super::super::Error;
use super::super::buffer::union_balanced;
use super::super::model::{Certainty, IssueScope, Status};
use super::super::stream::{CLIENT, peer};
use super::{ChainHead, Conn, Cx, Evidence, Fault, Pos, resources};
use crate::protocol::application::http2 as wire;
use bytes::Bytes;

use data::DataHead;

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
        let declared = (bytes.len() >= 9)
            .then(|| 9 + u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize);
        let take = if stream_error {
            let total = declared.expect("header length checked");
            if bytes.len() < total {
                return Ok(false);
            }
            cx.check_frames()?;
            self.frames += 1;
            total
        } else {
            // Attribute only the malformed frame to the issue when its declared
            // length is buffered; coalesced later frames stay terminal evidence.
            match declared {
                Some(total) if total <= bytes.len() => total,
                _ => dir.buffer.len(),
            }
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
        } else if let Some(id) = stream_id {
            self.reject_priority_stream(side, id, cx)?;
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
            } else if matches!(frame.payload, wire::Payload::Priority(_)) {
                self.reject_priority_stream(side, stream_id, cx)?;
            } else if matches!(frame.payload, wire::Payload::WindowUpdate { increment: 0 }) {
                // Preserve the idle/closed/capture-delayed classification even
                // when the control value itself is invalid.
                self.window_update(
                    side,
                    stream_id,
                    0,
                    Evidence {
                        wire: wire_bytes,
                        sources,
                    },
                    cx,
                )?;
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
}
