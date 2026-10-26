// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod data;
mod headers;

use super::super::Error;
use super::super::buffer::union_balanced;
use super::super::model::{Certainty, FrameBody, IssueScope, Status};
use super::{ChainHead, ConnectionState, Context, Evidence, Fault, Pos};
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::budget;
use crate::protocol::application::http2 as wire;
use bytes::Bytes;

use crate::analysis::http2::side::Side;
use data::DataHead;

impl ConnectionState {
    pub(crate) fn frame_step(
        &mut self,
        side: Side,
        context: &mut Context<'_>,
    ) -> Result<bool, Error> {
        context.check_deadline()?;
        if self.waiting_settings_ack(side) {
            return Ok(false);
        }
        {
            let dir = self
                .directions
                .get_mut(side)
                .ok_or(Error::Invariant("direction not found"))?;
            if dir.buffer.len() < wire::HEADER_LEN {
                return Ok(false);
            }
            let header = Bytes::copy_from_slice(&dir.buffer.bytes()[..wire::HEADER_LEN]);
            if let Err(error) =
                wire::parse_frame_for_analysis(&header, context.limits.max_frame_bytes)
            {
                return self.frame_fault(side, error, context);
            }
            let length = wire::declared_length(&header);
            let receiver = &self.control.settings[side.peer()];
            let effective_max = receiver.permitted_frame_size();
            if length as u32 > effective_max {
                let flow = dir.flow.clone();
                let sets = dir.buffer.contributors(wire::HEADER_LEN);
                let (_, dropped) = dir.buffer.take(wire::HEADER_LEN);
                let sources = union_balanced(sets)?;
                dir.release_consumed(wire::HEADER_LEN, dropped, context)?;
                self.reject(
                    context,
                    Fault::new(
                        flow,
                        IssueScope::Connection,
                        Status::Malformed,
                        IssueCode::FrameOverMaxSize,
                        format!("frame payload {length} exceeds the permitted maximum"),
                    )
                    .evidence(header, sources),
                )?;
                return Ok(true);
            }
            if dir.buffer.len() < wire::HEADER_LEN + length {
                return Ok(false);
            }
        }
        let dir = self
            .directions
            .get_mut(side)
            .ok_or(Error::Invariant("dir"))?;
        let length = wire::declared_length(dir.buffer.bytes());
        let total = wire::HEADER_LEN + length;
        let setting_words = size_of::<wire::Setting>();
        let scratch = total
            .checked_mul(2)
            .and_then(|v| {
                v.checked_add((length / 6).saturating_mul(setting_words.saturating_mul(2)))
            })
            .and_then(|v| {
                v.checked_add(
                    budget::EVENT_OVERHEAD + 4 * size_of::<super::super::settings::SettingIssue>(),
                )
            })
            .ok_or(Error::Application(
                crate::analysis::application::Error::Limit {
                    field: "frame_scratch",
                    limit: total,
                },
            ))?;
        context.reserve_scratch(scratch)?;
        let result = self.frame_step_parsed(side, total, context);
        context.release_scratch(scratch)?;
        result
    }

    fn frame_step_parsed(
        &mut self,
        side: Side,
        total: usize,
        context: &mut Context<'_>,
    ) -> Result<bool, Error> {
        let dir = self
            .directions
            .get_mut(side)
            .ok_or(Error::Invariant("dir"))?;
        let wire_bytes = Bytes::copy_from_slice(&dir.buffer.bytes()[..total]);
        let parsed = wire::parse_frame_for_analysis(&wire_bytes, context.limits.max_frame_bytes);
        match parsed {
            Ok(Some((frame, _))) => {
                context.check_frames()?;
                let dir = self
                    .directions
                    .get_mut(side)
                    .ok_or(Error::Invariant("dir"))?;
                let sets = dir.buffer.contributors(total);
                let dropped = dir.buffer.consume(total);
                dir.release_consumed(total, dropped, context)?;
                let sources = union_balanced(sets)?;
                self.frames += 1;
                self.handle_frame(side, frame, wire_bytes, sources, context)?;
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(error) => self.frame_fault(side, error, context),
        }
    }

    fn frame_fault(
        &mut self,
        side: Side,
        error: wire::Error,
        context: &mut Context<'_>,
    ) -> Result<bool, Error> {
        let dir = self
            .directions
            .get_mut(side)
            .ok_or(Error::Invariant("dir"))?;
        let bytes = dir.buffer.bytes();
        let priority_length_error = matches!(
            error,
            wire::Error::Invalid("frame has an invalid fixed length")
        ) && bytes.len() >= wire::HEADER_LEN
            && bytes[3] == wire::TYPE_PRIORITY;
        let interrupted_chain = priority_length_error && dir.chain.is_some();
        let stream_error = priority_length_error && !interrupted_chain;
        let stream_id = stream_error
            .then(|| u32::from_be_bytes([bytes[5] & 0x7f, bytes[6], bytes[7], bytes[8]]));
        let declared = (bytes.len() >= wire::HEADER_LEN)
            .then(|| wire::HEADER_LEN + wire::declared_length(bytes));
        let take = if stream_error {
            let total = declared.ok_or(Error::Invariant("header length checked"))?;
            if bytes.len() < total {
                return Ok(false);
            }
            context.check_frames()?;
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
        dir.release_consumed(take, dropped, context)?;
        let flow = dir.flow.clone();
        let (status, code, detail) = match &error {
            _ if interrupted_chain => (
                Status::Malformed,
                IssueCode::BrokenHeaderBlock,
                "an invalid PRIORITY frame interrupts an unfinished header block".to_owned(),
            ),
            wire::Error::Limit(limit) => (Status::Limit, IssueCode::FrameLimit, format!("{limit}")),
            wire::Error::Invalid(reason) => (
                Status::Malformed,
                IssueCode::FrameInvalid,
                (*reason).to_string(),
            ),
            wire::Error::Compression(reason) => (
                Status::Malformed,
                IssueCode::Compression,
                (*reason).to_string(),
            ),
        };
        self.issue(
            context,
            Fault::new(
                flow,
                if stream_error {
                    IssueScope::Stream
                } else {
                    IssueScope::Connection
                },
                status,
                code,
                detail,
            )
            .stream(stream_id)
            .evidence(wire, sources),
        )?;
        if !stream_error {
            self.fail(context, status)?;
        } else if let Some(id) = stream_id {
            self.reject_priority_stream(side, id, context)?;
        }
        Ok(true)
    }

    fn handle_frame(
        &mut self,
        side: Side,
        frame: wire::Frame,
        wire_bytes: Bytes,
        sources: Option<crate::analysis::provenance::SourceSet>,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let header = frame.header.clone();
        let stream_id = header.stream_id;
        let chained = self
            .directions
            .get(side)
            .and_then(|dir| dir.chain.as_ref().map(|chain| chain.stream_id));
        if let Some(chained) = chained {
            if header.frame_type != wire::TYPE_CONTINUATION || stream_id != chained {
                let flow = self.dir_flow(side);
                self.reject(
                    context,
                    Fault::new(
                        flow,
                        IssueScope::Connection,
                        Status::Malformed,
                        IssueCode::BrokenHeaderBlock,
                        "a frame interrupts an unfinished header block",
                    )
                    .stream(Some(stream_id))
                    .evidence(wire_bytes.clone(), sources.clone()),
                )?;
                return Ok(());
            }
        } else if header.frame_type == wire::TYPE_CONTINUATION {
            let flow = self.dir_flow(side);
            self.reject(
                context,
                Fault::new(
                    flow,
                    IssueScope::Connection,
                    Status::Malformed,
                    IssueCode::StrayContinuation,
                    "CONTINUATION does not follow a header block",
                )
                .stream(Some(stream_id))
                .evidence(wire_bytes.clone(), sources.clone()),
            )?;
            return Ok(());
        }
        let receiver = &self.control.settings[side.peer()];
        let effective_max = receiver.permitted_frame_size();
        if header.length > effective_max {
            let flow = self.dir_flow(side);
            self.issue(
                context,
                Fault::new(
                    flow,
                    IssueScope::Connection,
                    Status::Malformed,
                    IssueCode::FrameOverMaxSize,
                    format!(
                        "frame payload {} exceeds the permitted maximum",
                        header.length
                    ),
                )
                .stream((stream_id != 0).then_some(stream_id))
                .evidence(wire_bytes.slice(..wire::HEADER_LEN), sources.clone()),
            )?;
        } else if header.length
            > receiver
                .advertised
                .max_frame_size
                .min(receiver.acknowledged.max_frame_size)
        {
            let flow = self.dir_flow(side);
            self.issue(
                context,
                Fault::new(
                    flow,
                    IssueScope::Connection,
                    Status::Malformed,
                    IssueCode::FrameSizeOrdering,
                    format!(
                        "frame payload {} exceeds an unacknowledged bound",
                        header.length
                    ),
                )
                .stream((stream_id != 0).then_some(stream_id))
                .certainty(Certainty::ObservedOrder)
                .evidence(wire_bytes.slice(..wire::HEADER_LEN), sources.clone()),
            )?;
        }
        let control = match &frame.payload {
            wire::Payload::Control(control) => Some(control),
            wire::Payload::Data { .. } => None,
        };
        let semantic_error = match control {
            Some(
                wire::Control::Priority(priority)
                | wire::Control::Headers {
                    priority: Some(priority),
                    ..
                },
            ) if priority.dependency == stream_id => Some("priority depends on its own stream"),
            Some(wire::Control::WindowUpdate { increment: 0 }) => {
                Some("WINDOW_UPDATE has a zero increment")
            }
            _ => None,
        };
        if let Some(detail) = semantic_error {
            self.issue(
                context,
                Fault::new(
                    self.dir_flow(side),
                    if stream_id == 0 {
                        IssueScope::Connection
                    } else {
                        IssueScope::Stream
                    },
                    Status::Malformed,
                    IssueCode::FrameInvalid,
                    detail,
                )
                .stream((stream_id != 0).then_some(stream_id))
                .evidence(wire_bytes.clone(), sources.clone()),
            )?;
            if stream_id == 0 {
                self.fail(context, Status::Malformed)?;
                return Ok(());
            }
        }
        if semantic_error.is_some() && !matches!(control, Some(wire::Control::Headers { .. })) {
            // Invalid control values remain in the issue's exact wire evidence,
            // rather than being emitted as a valid typed control payload.
            if self.streams.open.contains_key(&stream_id) {
                self.close_stream(stream_id, Status::Malformed, None, context)?;
            } else if matches!(control, Some(wire::Control::Priority(_))) {
                self.reject_priority_stream(side, stream_id, context)?;
            } else if matches!(control, Some(wire::Control::WindowUpdate { increment: 0 })) {
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
                    context,
                )?;
            }
            return Ok(());
        }
        self.emit_frame(side, &frame, &wire_bytes, sources.clone(), context)?;
        self.apply_frame(
            side,
            frame,
            Evidence {
                wire: wire_bytes,
                sources,
            },
            context,
        )
    }

    fn emit_frame(
        &mut self,
        side: Side,
        frame: &wire::Frame,
        wire_bytes: &Bytes,
        sources: Option<crate::analysis::provenance::SourceSet>,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let body = match &frame.payload {
            wire::Payload::Data { data, padding } => FrameBody::Data {
                data_bytes: data.len() as u64,
                padding_bytes: padding.len(),
            },
            wire::Payload::Control(control) => FrameBody::Control {
                control: control.clone(),
                payload_wire: wire_bytes.slice(wire::HEADER_LEN..),
            },
        };
        let mut header_wire = [0u8; wire::HEADER_LEN];
        header_wire.copy_from_slice(&wire_bytes[..wire::HEADER_LEN]);
        let retained = match &body {
            FrameBody::Data { .. } => wire::HEADER_LEN,
            FrameBody::Control {
                control: wire::Control::Settings(values),
                ..
            } => wire_bytes.len() + values.capacity() * size_of::<wire::Setting>(),
            FrameBody::Control { .. } => wire_bytes.len(),
        };
        let sources = sources.ok_or(Error::Invariant("frame sources missing"))?;
        context.charge_retained(
            retained
                + budget::EVENT_OVERHEAD
                + budget::SET_OVERHEAD
                + sources.frames().len() * budget::SPAN_OVERHEAD,
        )?;
        context.frame(super::super::model::Frame {
            index: self.frames,
            stream: self.stream,
            generation: self.generation,
            flow: self.dir_flow(side),
            header: frame.header.clone(),
            header_wire,
            body,
            sources,
        });
        Ok(())
    }

    fn apply_frame(
        &mut self,
        side: Side,
        frame: wire::Frame,
        evidence: Evidence,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let flags = frame.header.flags;
        let stream_id = frame.header.stream_id;
        let first_frame = {
            let Some(dir) = self.directions.get_mut(side) else {
                return Ok(());
            };
            let first = !dir.saw_frame;
            dir.saw_frame = true;
            first
        };
        if first_frame
            && !(frame.header.frame_type == wire::TYPE_SETTINGS && flags & wire::FLAG_ACK == 0)
        {
            let certainty = if side == Side::Client || self.clean_start {
                Certainty::Confirmed
            } else {
                Certainty::Indeterminate
            };
            self.issue(
                context,
                Fault::new(
                    self.dir_flow(side),
                    IssueScope::Connection,
                    Status::Malformed,
                    IssueCode::MissingInitialSettings,
                    "the first frame on a direction was not a non-ACK SETTINGS",
                )
                .certainty(certainty)
                .evidence(
                    evidence.wire.slice(..wire::HEADER_LEN),
                    evidence.sources.clone(),
                ),
            )?;
            if certainty == Certainty::Confirmed {
                self.fail(context, Status::Malformed)?;
                return Ok(());
            }
        }
        let control = match frame.payload {
            wire::Payload::Data { data, .. } => {
                return self.data_frame(
                    DataHead {
                        side,
                        stream_id,
                        length: frame.header.length,
                        data_bytes: data.len() as u64,
                        end_stream: flags & wire::FLAG_END_STREAM != 0,
                    },
                    Evidence {
                        wire: Bytes::copy_from_slice(&evidence.wire[..wire::HEADER_LEN]),
                        sources: evidence.sources,
                    },
                    context,
                );
            }
            wire::Payload::Control(control) => control,
        };
        match control {
            wire::Control::Headers {
                fragment, priority, ..
            } => self.block_start(
                Pos { side, stream_id },
                ChainHead::Headers {
                    end_stream: flags & wire::FLAG_END_STREAM != 0,
                    malformed: priority.is_some_and(|priority| priority.dependency == stream_id),
                },
                fragment,
                evidence,
                context,
                flags & wire::FLAG_END_HEADERS != 0,
            ),
            wire::Control::Reset { .. } => self.reset_stream(side, stream_id, evidence, context),
            wire::Control::Settings(settings) => {
                self.settings_frame(side, flags, settings, evidence, context)
            }
            wire::Control::PushPromise {
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
                context,
                flags & wire::FLAG_END_HEADERS != 0,
            ),
            wire::Control::Ping(opaque) => self.ping_frame(side, flags, opaque, evidence, context),
            wire::Control::Priority(_) | wire::Control::Unknown(_) => Ok(()),
            wire::Control::Goaway { last_stream_id, .. } => {
                self.goaway_frame(side, last_stream_id, evidence, context)
            }
            wire::Control::WindowUpdate { increment } => {
                self.window_update(side, stream_id, increment, evidence, context)
            }
            wire::Control::Continuation(fragment) => {
                self.block_continue(side, stream_id, fragment, flags, evidence, context)
            }
        }
    }
}
