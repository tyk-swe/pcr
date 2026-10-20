// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Message construction, resource accounting, and ordered publication.

use super::super::{ConnectionState, Context, Decoded, Fault, Head, resources};
use crate::analysis::application;
use crate::analysis::http2::Error;
use crate::analysis::http2::buffer::union_balanced;
use crate::analysis::http2::model::{Certainty, IssueScope, Message, MessageKind, Status};
use crate::analysis::http2::stream::{CLIENT, FieldRole, MessageBuilder, SERVER};
use bytes::Bytes;

impl ConnectionState {
    pub(crate) fn new_message(
        &mut self,
        stream_id: u32,
        kind: MessageKind,
        context: &mut Context<'_>,
    ) -> Result<MessageBuilder, Error> {
        let index = context.check_messages()?;
        let mut msg = MessageBuilder::new(index, stream_id, kind);
        self.charge_conn(context, resources::MESSAGE_OVERHEAD)?;
        msg.charged = resources::MESSAGE_OVERHEAD;
        Ok(msg)
    }

    fn msg_content_charge(msg: &MessageBuilder) -> usize {
        msg.headers
            .iter()
            .map(|h| h.name.len() + h.value.len() + resources::HEADER_OVERHEAD)
            .sum::<usize>()
            + msg
                .trailers
                .iter()
                .map(|h| h.name.len() + h.value.len() + resources::HEADER_OVERHEAD)
                .sum::<usize>()
            + msg.header_blocks.iter().map(Bytes::len).sum::<usize>()
            + msg
                .upgrade_head
                .as_ref()
                .map_or(0, |head| head.wire().len())
    }

    pub(crate) fn emit_message(
        &mut self,
        side: usize,
        build: MessageBuilder,
        status: Status,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if status == Status::Complete
            && (self.waiting_settings_ack(CLIENT) || self.waiting_settings_ack(SERVER))
        {
            self.charge_conn(context, resources::PENDING_OVERHEAD)?;
            self.ack_deferred.push_back((side, build, status));
            return Ok(());
        }
        self.emit_message_with_completion(side, build, status, status == Status::Complete, context)
            .map(|_| ())
    }

    pub(super) fn emit_message_with_completion(
        &mut self,
        side: usize,
        mut build: MessageBuilder,
        status: Status,
        complete: bool,
        context: &mut Context<'_>,
    ) -> Result<Status, Error> {
        let (cl_exempt, connect_cl_illegal) = match build.status_code {
            Some(status) => {
                let stream = self.streams.get(&build.stream_id);
                let method = stream.and_then(|s| s.method.as_deref());
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
        if connect_cl_illegal {
            self.issue(
                context,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(build.stream_id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "connect_content_length",
                    detail: "a CONNECT 2xx response must not carry content-length".into(),
                    wire: build.header_blocks.last().cloned().unwrap_or_default(),
                    sources: union_balanced(build.sets.clone())?,
                },
            )?;
            build.failure = build.failure.or(Some(Status::Malformed));
        }
        if complete
            && !cl_exempt
            && let Some(declared) = build.content_length
            && declared != build.body_bytes
        {
            let flow = self.dir_flow(side);
            self.issue(
                context,
                Fault {
                    flow,
                    http2_stream_id: Some(build.stream_id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "content_length_mismatch",
                    detail: "observed body length does not match content-length".into(),
                    wire: Bytes::new(),
                    sources: None,
                },
            )?;
            build.failure = build.failure.or(Some(Status::Malformed));
        }
        let status = build.failure.unwrap_or(status);
        let sources = union_balanced(std::mem::take(&mut build.sets))?.ok_or(
            Error::Application(application::Error::Sources {
                number: self.number,
            }),
        )?;
        let compression_sources = union_balanced(std::mem::take(&mut build.compression))?;
        self.release_conn(context, build.charged);
        *context.spans = context
            .spans
            .checked_sub(build.charged_spans)
            .expect("msg spans");
        context.charge_retained(
            Self::msg_content_charge(&build)
                + resources::EVENT_OVERHEAD
                + resources::MESSAGE_OVERHEAD
                + resources::SET_OVERHEAD
                + sources.frames().len() * resources::SPAN_OVERHEAD
                + compression_sources.as_ref().map_or(0, |set| {
                    resources::SET_OVERHEAD + set.frames().len() * resources::SPAN_OVERHEAD
                }),
        )?;
        context.message(Message {
            index: build.index,
            stream: self.stream,
            generation: self.generation,
            http2_stream_id: build.stream_id,
            flow: self.dir_flow(side),
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
        side: usize,
        stream_id: u32,
        head: Head,
        decoded: Decoded,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let Head { role, meta, flawed } = head;
        let Decoded {
            headers,
            block,
            sources: block_sources,
            compression,
        } = decoded;
        let kind = match role {
            FieldRole::Request => MessageKind::Request,
            FieldRole::Response => match meta.status {
                Some(status) if (100..200).contains(&status) => MessageKind::Informational,
                _ => MessageKind::Response,
            },
            FieldRole::Trailer => {
                return Err(Error::Application(application::Error::Sources {
                    number: self.number,
                }));
            }
        };
        let mut msg = self.new_message(stream_id, kind, context)?;
        if flawed {
            msg.failure = Some(Status::Malformed);
        }
        let content_charge = headers
            .iter()
            .map(|h| h.name.len() + h.value.len() + resources::HEADER_OVERHEAD)
            .sum::<usize>()
            + block.len();
        self.charge_conn(context, content_charge)?;
        msg.charged += content_charge;
        msg.headers = headers;
        msg.header_blocks.push(block);
        msg.content_length = meta.content_length;
        msg.status_code = meta.status;
        if let Some(sources) = block_sources {
            let frames = sources.frames().len();
            let charge = resources::SET_OVERHEAD + frames * resources::SPAN_OVERHEAD;
            self.charge_conn(context, charge)?;
            context.charge_spans(frames)?;
            msg.charged += charge;
            msg.charged_spans += frames;
            msg.sets.push(sources);
        }
        if let Some(set) = compression {
            let frames = set.frames().len();
            let charge = resources::SET_OVERHEAD + frames * resources::SPAN_OVERHEAD;
            self.charge_conn(context, charge)?;
            context.charge_spans(frames)?;
            msg.charged += charge;
            msg.charged_spans += frames;
            msg.compression.push(set);
        }
        let stream = self.streams.get_mut(&stream_id).expect("stream");
        if let Some(method) = meta.method {
            stream.method = Some(method);
        }
        if role == FieldRole::Request {
            stream.request = Some(msg.index);
        } else {
            msg.request = stream.request;
        }
        msg.promised_by = stream.promised_by;
        if let Some(status) = meta.status {
            let head_request = stream.method.as_deref() == Some(b"HEAD");
            stream.response_bodyless =
                head_request || (100..200).contains(&status) || matches!(status, 204 | 205 | 304);
        }
        let unprocessed = stream.unprocessed;
        if kind == MessageKind::Informational {
            self.emit_message(
                side,
                msg,
                if unprocessed {
                    Status::Unprocessed
                } else {
                    Status::Complete
                },
                context,
            )?;
        } else {
            let stream = self.streams.get_mut(&stream_id).expect("stream");
            stream.msgs[side] = Some(msg);
        }
        if role == FieldRole::Request {
            self.release_parent_promises(stream_id, context)?;
        }
        Ok(())
    }

    pub(crate) fn release_ack_deferred_messages(
        &mut self,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if self.waiting_settings_ack(CLIENT) || self.waiting_settings_ack(SERVER) {
            return Ok(());
        }
        let immediate = std::mem::take(&mut self.ack_deferred);
        self.release_conn(context, immediate.len() * resources::PENDING_OVERHEAD);
        for (side, msg, status) in immediate {
            context.check_deadline()?;
            self.emit_message(side, msg, status, context)?;
        }
        let scratch = self
            .streams
            .len()
            .saturating_mul(2 * size_of::<(usize, u32)>());
        context.charge_live(scratch)?;
        let result = (|| {
            let mut completed = Vec::with_capacity(self.streams.len().saturating_mul(2));
            for (id, stream) in &self.streams {
                context.check_deadline()?;
                for side in [CLIENT, SERVER] {
                    if stream.ended[side] && stream.msgs[side].is_some() {
                        completed.push((side, *id));
                    }
                }
            }
            for (side, id) in completed {
                context.check_deadline()?;
                self.end_side(side, id, Status::Complete, context)?;
            }
            Ok(())
        })();
        context.release_live(scratch);
        result
    }
}
