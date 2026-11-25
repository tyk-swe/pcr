// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Frame boundary decoding, continuation/size/semantic checks, and dispatch.

mod data;
mod headers;

use super::super::Error;
use super::super::buffer::union_balanced;
use super::super::model::{Certainty, IssueScope, Status};
use super::{
    ActiveState, ChainHead, Context, Evidence, Fault, Pos, Reporter, StepAbort, StepResult,
};
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::budget;
use crate::analysis::http2::side::Side;
use crate::analysis::provenance::SourceSet;
use crate::protocol::application::http2 as wire;
use bytes::Bytes;
use data::DataHead;
use headers::{BlockContinue, BlockStart};

fn frame_scratch_bytes(length: usize, total: usize) -> Result<usize, Error> {
    let setting_words = size_of::<wire::Setting>();
    total
        .checked_mul(2)
        .and_then(|v| v.checked_add((length / 6).saturating_mul(setting_words.saturating_mul(2))))
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
        ))
}

impl ActiveState {
    pub(crate) fn frame_step(
        &mut self,
        side: Side,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<bool> {
        context.check_deadline()?;
        if self.waiting_settings_ack(side) {
            return Ok(false);
        }
        let Some(total) = self.peek_ready_frame(side, reporter, context)? else {
            return Ok(false);
        };
        let length = total - wire::HEADER_LEN;
        let scratch = frame_scratch_bytes(length, total)?;
        context.with_scratch(scratch, |context| {
            self.frame_step_parsed(side, total, reporter, context)
        })
    }

    fn peek_ready_frame(
        &mut self,
        side: Side,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<Option<usize>> {
        let effective_max = self.control.settings[side.peer()].permitted_frame_size();
        let Some(dir) = self.directions.get_mut(side) else {
            return Ok(None);
        };
        if dir.buffer.len() < wire::HEADER_LEN {
            return Ok(None);
        }
        let header = Bytes::copy_from_slice(&dir.buffer.bytes()[..wire::HEADER_LEN]);
        if let Err(error) = wire::parse_frame_for_analysis(&header, context.limits.max_frame_bytes)
        {
            self.frame_fault(side, error, reporter, context)?;
            return Ok(None);
        }
        let length = wire::declared_length(&header);
        if length as u32 > effective_max {
            let flow = dir.flow.clone();
            let sets = dir.buffer.consume(wire::HEADER_LEN, context)?;
            let sources = union_balanced(sets)?;
            return reporter.reject(
                context,
                Fault::connection(
                    flow,
                    Status::Malformed,
                    IssueCode::FrameOverMaxSize,
                    format!("frame payload {length} exceeds the permitted maximum"),
                )
                .with_evidence(header, sources),
            );
        }
        let total = wire::HEADER_LEN + length;
        if dir.buffer.len() < total {
            return Ok(None);
        }
        Ok(Some(total))
    }

    fn frame_step_parsed(
        &mut self,
        side: Side,
        total: usize,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<bool> {
        let Some(dir) = self.directions.get_mut(side) else {
            return Ok(false);
        };
        let wire_bytes = Bytes::copy_from_slice(&dir.buffer.bytes()[..total]);
        match wire::parse_frame_for_analysis(&wire_bytes, context.limits.max_frame_bytes) {
            Ok(Some((frame, _))) => {
                context.check_frames()?;
                let sets = dir.buffer.consume(total, context)?;
                let sources = union_balanced(sets)?;
                reporter.frames += 1;
                self.handle_frame(side, frame, wire_bytes, sources, reporter, context)?;
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(error) => self.frame_fault(side, error, reporter, context),
        }
    }

    fn frame_fault(
        &mut self,
        side: Side,
        error: wire::Error,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<bool> {
        let Some(dir) = self.directions.get_mut(side) else {
            return Ok(false);
        };
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
        let take = match (stream_error, declared) {
            (true, Some(total)) => {
                if bytes.len() < total {
                    return Ok(false);
                }
                context.check_frames()?;
                reporter.frames += 1;
                total
            }
            // Attribute only the malformed frame to the issue when its declared
            // length is buffered; coalesced later frames stay terminal evidence.
            (_, Some(total)) if total <= bytes.len() => total,
            _ => dir.buffer.len(),
        };
        let (wire, sets) = dir.buffer.take(take, context)?;
        let sources = union_balanced(sets)?;
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
        let scope = if stream_error {
            IssueScope::Stream
        } else {
            IssueScope::Connection
        };
        reporter.issue(
            context,
            Fault::new(flow, scope, status, code, detail)
                .with_stream(stream_id)
                .with_evidence(wire, sources),
        )?;
        if !stream_error {
            return Err(StepAbort::ConnectionFailed(status));
        }
        if let Some(id) = stream_id {
            self.reject_priority_stream(side, id, reporter, context)?;
        }
        Ok(true)
    }

    fn handle_frame(
        &mut self,
        side: Side,
        frame: wire::Frame,
        wire_bytes: Bytes,
        sources: Option<SourceSet>,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        let evidence = Evidence::new(wire_bytes, sources);
        self.check_continuation(side, &frame.header, &evidence, reporter, context)?;
        self.check_frame_size(side, &frame.header, &evidence, reporter, context)?;
        if self.check_control_semantics(side, &frame, &evidence, reporter, context)? {
            return Ok(());
        }
        reporter.emit_frame(
            self.directions.flow(side),
            &frame,
            &evidence.wire,
            evidence.sources.clone(),
            context,
        )?;
        self.apply_frame(side, frame, evidence, reporter, context)
    }

    fn check_continuation(
        &self,
        side: Side,
        header: &wire::FrameHeader,
        evidence: &Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        let chained = self
            .directions
            .get(side)
            .and_then(|dir| dir.chain.as_ref().map(|chain| chain.stream_id));
        if let Some(chained) = chained {
            if header.frame_type != wire::TYPE_CONTINUATION || header.stream_id != chained {
                return reporter.reject(
                    context,
                    Fault::connection(
                        self.directions.flow(side),
                        Status::Malformed,
                        IssueCode::BrokenHeaderBlock,
                        "a frame interrupts an unfinished header block",
                    )
                    .with_stream(Some(header.stream_id))
                    .with_evidence_ref(evidence),
                );
            }
        } else if header.frame_type == wire::TYPE_CONTINUATION {
            return reporter.reject(
                context,
                Fault::connection(
                    self.directions.flow(side),
                    Status::Malformed,
                    IssueCode::StrayContinuation,
                    "CONTINUATION does not follow a header block",
                )
                .with_stream(Some(header.stream_id))
                .with_evidence_ref(evidence),
            );
        }
        Ok(())
    }

    fn check_frame_size(
        &self,
        side: Side,
        header: &wire::FrameHeader,
        evidence: &Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let receiver = &self.control.settings[side.peer()];
        let stream_opt = (header.stream_id != 0).then_some(header.stream_id);
        let header_wire = evidence.wire.slice(..wire::HEADER_LEN);
        if header.length > receiver.permitted_frame_size() {
            reporter.issue(
                context,
                Fault::connection(
                    self.directions.flow(side),
                    Status::Malformed,
                    IssueCode::FrameOverMaxSize,
                    format!(
                        "frame payload {} exceeds the permitted maximum",
                        header.length
                    ),
                )
                .with_stream(stream_opt)
                .with_evidence(header_wire, evidence.sources.clone()),
            )?;
        } else if header.length
            > receiver
                .advertised
                .max_frame_size
                .min(receiver.acknowledged.max_frame_size)
        {
            reporter.issue(
                context,
                Fault::connection(
                    self.directions.flow(side),
                    Status::Malformed,
                    IssueCode::FrameSizeOrdering,
                    format!(
                        "frame payload {} exceeds an unacknowledged bound",
                        header.length
                    ),
                )
                .with_stream(stream_opt)
                .with_certainty(Certainty::ObservedOrder)
                .with_evidence(header_wire, evidence.sources.clone()),
            )?;
        }
        Ok(())
    }

    /// Validates control frame invariants that depend on stream id or payload
    /// values. Returns `Ok(true)` when the frame has been handled and should not
    /// be emitted or dispatched further.
    fn check_control_semantics(
        &mut self,
        side: Side,
        frame: &wire::Frame,
        evidence: &Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<bool> {
        let stream_id = frame.header.stream_id;
        let wire::Payload::Control(control) = &frame.payload else {
            return Ok(false);
        };
        let detail = match control {
            wire::Control::Priority(priority)
            | wire::Control::Headers {
                priority: Some(priority),
                ..
            } if priority.dependency == stream_id => "priority depends on its own stream",
            wire::Control::WindowUpdate { increment: 0 } => "WINDOW_UPDATE has a zero increment",
            _ => return Ok(false),
        };
        let scope = if stream_id == 0 {
            IssueScope::Connection
        } else {
            IssueScope::Stream
        };
        reporter.issue(
            context,
            Fault::new(
                self.directions.flow(side),
                scope,
                Status::Malformed,
                IssueCode::FrameInvalid,
                detail,
            )
            .with_stream((stream_id != 0).then_some(stream_id))
            .with_evidence_ref(evidence),
        )?;
        if stream_id == 0 {
            return Err(StepAbort::ConnectionFailed(Status::Malformed));
        }
        if matches!(control, wire::Control::Headers { .. }) {
            return Ok(false);
        }
        // Invalid control values remain in the issue's exact wire evidence,
        // rather than being emitted as a valid typed control payload.
        if self.streams.is_open(stream_id) {
            self.close_stream(stream_id, Status::Malformed, None, reporter, context)?;
        } else if matches!(control, wire::Control::Priority(_)) {
            self.reject_priority_stream(side, stream_id, reporter, context)?;
        } else if matches!(control, wire::Control::WindowUpdate { increment: 0 }) {
            // Preserve the idle/closed/capture-delayed classification even
            // when the control value itself is invalid.
            self.window_update(side, stream_id, 0, evidence.clone(), reporter, context)?;
        }
        Ok(true)
    }

    fn apply_frame(
        &mut self,
        side: Side,
        frame: wire::Frame,
        evidence: Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        let flags = frame.header.flags;
        let stream_id = frame.header.stream_id;
        let Some(dir) = self.directions.get_mut(side) else {
            return Ok(());
        };
        let first_frame = !dir.saw_frame;
        dir.saw_frame = true;
        if first_frame
            && !(frame.header.frame_type == wire::TYPE_SETTINGS && flags & wire::FLAG_ACK == 0)
        {
            let certainty = if side == Side::Client || self.clean_start {
                Certainty::Confirmed
            } else {
                Certainty::Indeterminate
            };
            reporter.issue(
                context,
                Fault::connection(
                    self.directions.flow(side),
                    Status::Malformed,
                    IssueCode::MissingInitialSettings,
                    "the first frame on a direction was not a non-ACK SETTINGS",
                )
                .with_certainty(certainty)
                .with_evidence(
                    evidence.wire.slice(..wire::HEADER_LEN),
                    evidence.sources.clone(),
                ),
            )?;
            if certainty == Certainty::Confirmed {
                return Err(StepAbort::ConnectionFailed(Status::Malformed));
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
                    Evidence::new(
                        Bytes::copy_from_slice(&evidence.wire[..wire::HEADER_LEN]),
                        evidence.sources,
                    ),
                    reporter,
                    context,
                );
            }
            wire::Payload::Control(control) => control,
        };
        match control {
            wire::Control::Headers {
                fragment, priority, ..
            } => self.block_start(
                BlockStart {
                    at: Pos { side, stream_id },
                    head: ChainHead::Headers {
                        end_stream: flags & wire::FLAG_END_STREAM != 0,
                        malformed: priority
                            .is_some_and(|priority| priority.dependency == stream_id),
                    },
                    fragment,
                    evidence,
                    end_headers: flags & wire::FLAG_END_HEADERS != 0,
                },
                reporter,
                context,
            ),
            wire::Control::Reset { .. } => {
                self.reset_stream(side, stream_id, evidence, reporter, context)
            }
            wire::Control::Settings(settings) => {
                self.settings_frame(side, flags, settings, evidence, reporter, context)
            }
            wire::Control::PushPromise {
                promised_stream_id,
                fragment,
                ..
            } => self.block_start(
                BlockStart {
                    at: Pos { side, stream_id },
                    head: ChainHead::PushPromise {
                        promised: promised_stream_id,
                    },
                    fragment,
                    evidence,
                    end_headers: flags & wire::FLAG_END_HEADERS != 0,
                },
                reporter,
                context,
            ),
            wire::Control::Ping(opaque) => {
                self.ping_frame(side, flags, opaque, evidence, reporter, context)?;
                Ok(())
            }
            wire::Control::Priority(_) | wire::Control::Unknown(_) => Ok(()),
            wire::Control::Goaway { last_stream_id, .. } => {
                self.goaway_frame(side, last_stream_id, evidence, reporter, context)
            }
            wire::Control::WindowUpdate { increment } => {
                self.window_update(side, stream_id, increment, evidence, reporter, context)
            }
            wire::Control::Continuation(fragment) => self.block_continue(
                BlockContinue {
                    at: Pos { side, stream_id },
                    fragment,
                    end_headers: flags & wire::FLAG_END_HEADERS != 0,
                    evidence,
                },
                reporter,
                context,
            ),
        }
    }
}
