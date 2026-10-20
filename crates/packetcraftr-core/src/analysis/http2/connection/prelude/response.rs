// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::super::Error;
use super::super::super::buffer::union_balanced;
use super::super::super::model::{Certainty, Header, IssueScope, MessageKind, Status};
use super::super::super::stream::{CLIENT, SERVER};
use super::super::super::upgrade;
use super::super::{ConnectionState, Context, Fault, Phase, resources};
use crate::analysis::application;
use crate::protocol::application::http::{self, BodyDecoder, StartLine};
use bytes::Bytes;

impl ConnectionState {
    pub(in super::super) fn report_unmatched_response_at_eof(
        &mut self,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if !matches!(self.phase, Phase::Prelude)
            || !self.prelude.as_ref().is_some_and(|p| p.requests.is_empty())
        {
            return Ok(());
        }
        let Some(dir) = self.dirs[SERVER].as_ref() else {
            return Ok(());
        };
        let need = dir.buffer.len().min(http::MAX_HEADER_BYTES + 1);
        if need == 0 {
            return Ok(());
        }
        let uncertain = !self.clean_start
            || self.status != Status::Complete
            || self.dirs[CLIENT]
                .as_ref()
                .is_some_and(|dir| !dir.buffer.is_empty())
            || self
                .prelude
                .as_ref()
                .is_some_and(|p| p.live_request.is_some());
        let scratch = need * 4 + resources::PRELUDE_HEADER_OVERHEAD;
        context.charge_live(scratch)?;
        let result = (|| {
            let dir = self.dirs[SERVER].as_mut().expect("server");
            let view = Bytes::copy_from_slice(&dir.buffer.bytes()[..need]);
            let Ok(Some((head, consumed))) = http::parse_head(&view) else {
                return Ok(());
            };
            if !matches!(head.start, StartLine::Response { .. }) {
                return Ok(());
            }
            let sets = dir.buffer.contributors(consumed);
            let (wire, dropped) = dir.buffer.take(consumed);
            Self::release_dir(dir, context, consumed);
            Self::release_dropped(dir, dropped, context);
            self.issue(
                context,
                Fault {
                    flow: self.dir_flow(SERVER),
                    http2_stream_id: None,
                    scope: IssueScope::Connection,
                    certainty: if !uncertain {
                        Certainty::Confirmed
                    } else {
                        Certainty::Indeterminate
                    },
                    status: if !uncertain {
                        Status::Malformed
                    } else {
                        Status::Incomplete
                    },
                    code: "prelude_unsolicited_response",
                    detail: "capture ended without a request matching this HTTP/1 response".into(),
                    wire,
                    sources: union_balanced(sets)?,
                },
            )
        })();
        context.release_live(scratch);
        result
    }

    pub(super) fn server_prelude_step(&mut self, context: &mut Context<'_>) -> Result<bool, Error> {
        let unmatched = self.prelude.as_ref().is_some_and(|p| p.requests.is_empty());
        let partial_request = self.dirs[CLIENT]
            .as_ref()
            .is_some_and(|dir| !dir.buffer.is_empty());
        if unmatched && (!self.clean_start || partial_request) {
            // Capture order can expose a response before the request head is
            // complete. Keep its bytes and sources in the charged direction
            // buffer; the next client delivery pumps this direction again.
            return Ok(false);
        }
        let dir =
            self.dirs[SERVER]
                .as_mut()
                .ok_or(Error::Application(application::Error::Sources {
                    number: self.number,
                }))?;
        let need = dir.buffer.len().min(http::MAX_HEADER_BYTES + 1);
        let view = Bytes::copy_from_slice(&dir.buffer.bytes()[..need]);
        let (head, consumed) = match http::parse_head(&view) {
            Ok(Some(found)) => found,
            Ok(None) => return Ok(false),
            Err(error) => {
                let flow = dir.flow.clone();
                let take = dir.buffer.len();
                let sets = dir.buffer.contributors(take);
                let (wire, dropped) = dir.buffer.take(take);
                let sources = union_balanced(sets)?;
                Self::release_dir(dir, context, take);
                Self::release_dropped(dir, dropped, context);
                self.issue(
                    context,
                    Fault {
                        flow,
                        http2_stream_id: None,
                        scope: IssueScope::Connection,
                        certainty: Certainty::Confirmed,
                        status: Status::Malformed,
                        code: "prelude_head",
                        detail: error.to_string().into(),
                        wire,
                        sources,
                    },
                )?;
                self.fail(context, Status::Malformed)?;
                return Ok(true);
            }
        };
        if !matches!(head.start, StartLine::Response { .. }) {
            let flow = dir.flow.clone();
            let release_len = consumed.min(dir.buffer.len());
            let sets = dir.buffer.contributors(release_len);
            let (_, dropped) = dir.buffer.take(release_len);
            let sources = union_balanced(sets)?;
            Self::release_dir(dir, context, release_len);
            Self::release_dropped(dir, dropped, context);
            self.issue(
                context,
                Fault {
                    flow,
                    http2_stream_id: None,
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "prelude_not_response",
                    detail: "the server direction did not carry a response head".into(),
                    wire: Bytes::copy_from_slice(&view[..consumed.min(256)]),
                    sources,
                },
            )?;
            self.fail(context, Status::Malformed)?;
            return Ok(true);
        }
        let sets = dir.buffer.contributors(consumed);
        let (head_wire_bytes, dropped) = dir.buffer.take(consumed);
        Self::release_dir(dir, context, consumed);
        Self::release_dropped(dir, dropped, context);
        let (head, _) =
            http::parse_head(&head_wire_bytes)?.expect("previously parsed complete HTTP/1 head");
        let head_wire = head_wire_bytes.len();
        let status = head.status().expect("response");
        let front = self.prelude.as_mut().and_then(|p| {
            p.requests
                .front()
                .map(|p| (p.index, p.method.clone(), p.upgrade))
        });
        let matched = front.as_ref().is_some_and(|(index, _, upgrade)| {
            *upgrade
                && self
                    .prelude
                    .as_ref()
                    .is_some_and(|p| p.offers.contains_key(index))
        });
        if status < 200
            && (head.values("content-length").next().is_some()
                || head.values("transfer-encoding").next().is_some())
        {
            self.issue(
                context,
                Fault {
                    flow: self.dir_flow(SERVER),
                    http2_stream_id: None,
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "prelude_framing",
                    detail:
                        "informational responses cannot contain Content-Length or Transfer-Encoding"
                            .into(),
                    wire: head_wire_bytes,
                    sources: union_balanced(sets)?,
                },
            )?;
            self.fail(context, Status::Malformed)?;
            return Ok(true);
        }
        if status == 101 {
            if matched && upgrade::accepts_upgrade(&head) {
                let (index, method, _) = front.clone().expect("front");
                let prelude = self.prelude.as_mut().expect("prelude");
                prelude.requests.pop_front();
                self.release_conn(context, resources::PENDING_OVERHEAD);
                self.accept_upgrade(index, head, head_wire_bytes, sets, method, context)?;
                return Ok(true);
            }
            self.issue(
                context,
                Fault {
                    flow: self.dir_flow(SERVER),
                    http2_stream_id: None,
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Unsupported,
                    code: "unexpected_101",
                    detail: "a 101 response does not match a pending h2c offer".into(),
                    wire: head_wire_bytes,
                    sources: union_balanced(sets)?,
                },
            )?;
            self.fail(context, Status::Unsupported)?;
            return Ok(true);
        }
        if front.is_none() {
            self.issue(
                context,
                Fault {
                    flow: self.dir_flow(SERVER),
                    http2_stream_id: None,
                    scope: IssueScope::Connection,
                    certainty: if self.clean_start {
                        Certainty::Confirmed
                    } else {
                        Certainty::Indeterminate
                    },
                    status: Status::Malformed,
                    code: "prelude_unsolicited_response",
                    detail: "HTTP/1 response has no pending request".into(),
                    wire: head_wire_bytes,
                    sources: union_balanced(sets)?,
                },
            )?;
            self.fail(context, Status::Malformed)?;
            return Ok(true);
        }
        let mut msg = self.new_message(0, MessageKind::Response, context)?;
        self.charge_conn(context, head_wire)?;
        msg.charged += head_wire;
        let header_charge = head
            .headers
            .iter()
            .map(|h| h.name.len() + h.value.len() + resources::HEADER_OVERHEAD)
            .sum::<usize>();
        self.charge_conn(context, header_charge)?;
        msg.charged += header_charge;
        let headers: Vec<Header> = head
            .headers
            .iter()
            .map(|header| Header {
                name: Bytes::copy_from_slice(header.name.as_bytes()),
                value: header.value.clone(),
                never_indexed: false,
            })
            .collect();
        msg.headers = headers;
        for set in sets {
            let frames = set.frames().len();
            let charge = resources::SET_OVERHEAD + frames * resources::SPAN_OVERHEAD;
            self.charge_conn(context, charge)?;
            context.charge_spans(frames)?;
            msg.charged += charge;
            msg.charged_spans += frames;
            msg.sets.push(set);
        }
        if let Some((index, ..)) = front {
            msg.request = Some(index);
        }
        let informational = status < 200;
        if informational {
            self.drop_msg(msg, context);
            return Ok(true);
        }
        let had_front = front.is_some();
        let (front_index, method, was_upgrade) = front.unwrap_or((0, None, false));
        if had_front {
            let prelude = self.prelude.as_mut().expect("prelude");
            prelude.requests.pop_front();
            self.release_conn(context, resources::PENDING_OVERHEAD);
        }
        if was_upgrade {
            if let Some(mut offer) = self
                .prelude
                .as_mut()
                .and_then(|prelude| prelude.offers.remove(&front_index))
            {
                self.release_conn(
                    context,
                    resources::OFFER_OVERHEAD + offer.settings.capacity() * 24,
                );
                if let Some(held) = offer.msg.take() {
                    self.refused_upgrade(held, context)?;
                }
            }
            let live = self.prelude.as_mut().and_then(|prelude| {
                if prelude
                    .live_request
                    .as_ref()
                    .is_some_and(|msg| msg.index == front_index)
                {
                    prelude.live_request.take()
                } else {
                    None
                }
            });
            if let Some(live) = live {
                self.refused_upgrade(live, context)?;
            }
            self.refused = true;
        }
        let framing = match head.body(method.as_deref()) {
            Ok(framing) => framing,
            Err(error) => {
                let sources = union_balanced(std::mem::take(&mut msg.sets))?;
                self.drop_msg(msg, context);
                self.issue(
                    context,
                    Fault {
                        flow: self.dir_flow(SERVER),
                        http2_stream_id: None,
                        scope: IssueScope::Connection,
                        certainty: Certainty::Confirmed,
                        status: Status::Malformed,
                        code: "prelude_framing",
                        detail: error.to_string().into(),
                        wire: head.wire().clone(),
                        sources,
                    },
                )?;
                self.fail(context, Status::Malformed)?;
                return Ok(true);
            }
        };
        if matches!(framing, http::Body::Chunked) {
            if let Err(error) = self.charge_conn(context, resources::PRELUDE_BODY_RESERVE) {
                self.drop_msg(msg, context);
                return Err(error);
            }
            self.prelude.as_mut().expect("prelude").body_charge[SERVER] =
                resources::PRELUDE_BODY_RESERVE;
        }
        let decoder = BodyDecoder::new(framing, context.limits.max_body_bytes);
        if decoder.complete() {
            self.drop_msg(msg, context);
        } else {
            let prelude = self.prelude.as_mut().expect("prelude");
            prelude.server_body = Some(decoder);
            prelude.live_response = Some(msg);
        }
        Ok(true)
    }
}
