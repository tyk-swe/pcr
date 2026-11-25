// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Message construction, resource accounting, and ordered publication.

use super::super::{ActiveState, Context, Fault, Head, Reporter, StepResult};
use crate::analysis::http_headers::final_status_forbids_content;
use crate::analysis::http2::budget;
use crate::analysis::http2::buffer::union_balanced;
use crate::analysis::http2::model::{Message, MessageKind, Status};
use crate::analysis::http2::side::Side;
use crate::analysis::http2::stream::{Decoded, HeadKind, HeaderSection, MessageBuilder};
use crate::analysis::http2::{Error, IssueCode};

impl ActiveState {
    pub(crate) fn new_message(
        stream_id: u32,
        kind: MessageKind,
        context: &mut Context<'_>,
    ) -> Result<MessageBuilder, Error> {
        let index = context.check_messages()?;
        let mut msg = MessageBuilder::new(index, stream_id, kind);
        context.charge(&mut msg.charge, budget::MESSAGE_OVERHEAD)?;
        Ok(msg)
    }

    pub(crate) fn emit_message(
        &mut self,
        side: Side,
        build: MessageBuilder,
        status: Status,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if status == Status::Complete && self.waiting_any_settings_ack() {
            return self
                .deferred
                .push_awaiting_ack(side, build, status, context);
        }
        self.emit_message_with_completion(
            side,
            build,
            status,
            status == Status::Complete,
            reporter,
            context,
        )
        .map(|_| ())
    }

    pub(super) fn emit_message_with_completion(
        &self,
        side: Side,
        mut build: MessageBuilder,
        status: Status,
        complete: bool,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> Result<Status, Error> {
        let (cl_exempt, connect_cl_illegal) = match build.status_code {
            Some(status) => {
                let method = self
                    .streams
                    .open_get(build.stream_id)
                    .and_then(|stream| stream.method.as_deref());
                let connect = method == Some(b"CONNECT") && (200..300).contains(&status);
                (
                    method == Some(b"HEAD")
                        || status == 304
                        || (100..200).contains(&status)
                        || status == 204
                        || connect,
                    connect && build.content_length.is_some(),
                )
            }
            None => (false, false),
        };
        let flow = self.directions.flow(side);
        if connect_cl_illegal {
            reporter.issue(
                context,
                Fault::stream(
                    flow.clone(),
                    build.stream_id,
                    Status::Malformed,
                    IssueCode::ConnectContentLength,
                    "a CONNECT 2xx response must not carry content-length",
                )
                .with_evidence(
                    build.header_blocks.last().cloned().unwrap_or_default(),
                    union_balanced(build.sets.clone())?,
                ),
            )?;
            build.failure = build.failure.or(Some(Status::Malformed));
        }
        if complete
            && !cl_exempt
            && let Some(declared) = build.content_length
            && declared != build.body_bytes
        {
            reporter.issue(
                context,
                Fault::stream(
                    flow.clone(),
                    build.stream_id,
                    Status::Malformed,
                    IssueCode::ContentLengthMismatch,
                    "observed body length does not match content-length",
                ),
            )?;
            build.failure = build.failure.or(Some(Status::Malformed));
        }
        let status = build.failure.unwrap_or(status);
        let sources = union_balanced(std::mem::take(&mut build.sets))?
            .ok_or(Error::Invariant("message sources missing"))?;
        let compression_sources = union_balanced(std::mem::take(&mut build.compression))?;
        context.release_all(&mut build.charge)?;
        context.charge_retained(
            build.content_charge()
                + budget::EVENT_OVERHEAD
                + budget::MESSAGE_OVERHEAD
                + budget::set_cost(&sources)
                + compression_sources.as_ref().map_or(0, budget::set_cost),
        )?;
        context.message(Message {
            index: build.index,
            stream: reporter.stream,
            generation: reporter.generation,
            http2_stream_id: build.stream_id,
            flow,
            kind: build.kind,
            request: build.request,
            promised_by: build.promised_by,
            status,
            headers: build.headers,
            trailers: build.trailers,
            header_blocks: build.header_blocks,
            upgrade_head: build.upgrade_head,
            body_bytes: build.body_bytes,
            sources,
            compression_sources,
        });
        Ok(status)
    }

    pub(crate) fn start_message(
        &mut self,
        side: Side,
        stream_id: u32,
        head: Head,
        decoded: Decoded,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let Head { kind, meta, flawed } = head;
        let msg_kind = match kind {
            HeadKind::Request => MessageKind::Request,
            HeadKind::Response => match meta.status {
                Some(status) if (100..200).contains(&status) => MessageKind::Informational,
                _ => MessageKind::Response,
            },
        };
        let mut msg = Self::new_message(stream_id, msg_kind, context)?;
        if flawed {
            msg.failure = Some(Status::Malformed);
        }
        msg.retain_headers(HeaderSection::Initial, decoded, context)?;
        msg.content_length = meta.content_length;
        msg.status_code = meta.status;
        let Some(stream) = self.streams.open_mut(stream_id) else {
            context.release_all(&mut msg.charge)?;
            return Err(Error::Invariant("stream"));
        };
        if let Some(method) = meta.method {
            stream.method = Some(method);
        }
        if kind == HeadKind::Request {
            stream.request = Some(msg.index);
        } else {
            msg.request = stream.request;
        }
        msg.promised_by = stream.promised_by;
        if let Some(status) = meta.status {
            let head_request = stream.method.as_deref() == Some(b"HEAD");
            stream.response_bodyless = head_request
                || (100..200).contains(&status)
                || final_status_forbids_content(status);
        }
        let unprocessed = stream.unprocessed;
        if msg_kind == MessageKind::Informational {
            let emit_status = if unprocessed {
                Status::Unprocessed
            } else {
                Status::Complete
            };
            self.emit_message(side, msg, emit_status, reporter, context)?;
        } else {
            stream.msgs[side] = Some(msg);
        }
        if kind == HeadKind::Request {
            self.release_parent_promises(stream_id, reporter, context)?;
        }
        Ok(())
    }

    pub(crate) fn release_ack_deferred_messages(
        &mut self,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        if self.waiting_any_settings_ack() {
            return Ok(());
        }
        for (side, msg, status) in self.deferred.take_all_awaiting_ack(context)? {
            context.check_deadline()?;
            self.emit_message(side, msg, status, reporter, context)?;
        }
        let scratch = self
            .streams
            .open_len()
            .saturating_mul(2 * size_of::<(Side, u32)>());
        context.with_scratch(scratch, |context| {
            let mut completed = Vec::with_capacity(self.streams.open_len().saturating_mul(2));
            for (id, stream) in self.streams.open_iter() {
                context.check_deadline()?;
                for side in Side::BOTH {
                    if stream.ended[side] && stream.msgs[side].is_some() {
                        completed.push((side, id));
                    }
                }
            }
            for (side, id) in completed {
                context.check_deadline()?;
                self.end_side(side, id, Status::Complete, reporter, context)?;
            }
            Ok(())
        })
    }
}
