// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::super::Error;
use super::super::super::buffer::union_balanced;
use super::super::super::model::{Certainty, Header, IssueScope, MessageKind, Status};
use super::super::super::upgrade::{self, Offer, Pending};
use super::super::{ConnectionState, Context, Fault, resources};
use crate::analysis::http2::side::Side;
use crate::protocol::application::http::{self, BodyDecoder, StartLine};
use bytes::Bytes;

impl ConnectionState {
    pub(super) fn client_prelude_step(&mut self, context: &mut Context<'_>) -> Result<bool, Error> {
        let dir = self.dirs[Side::Client]
            .as_mut()
            .ok_or(Error::Invariant("direction not found"))?;
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
                Self::release_dir(dir, context, take)?;
                Self::release_dropped(dir, dropped, context)?;
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
        if !matches!(head.start, StartLine::Request { .. }) {
            let flow = dir.flow.clone();
            let sets = dir.buffer.contributors(consumed.min(dir.buffer.len()));
            let (_, dropped) = dir.buffer.take(consumed.min(dir.buffer.len()));
            let sources = union_balanced(sets)?;
            Self::release_dir(dir, context, consumed)?;
            Self::release_dropped(dir, dropped, context)?;
            self.issue(
                context,
                Fault {
                    flow,
                    http2_stream_id: None,
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "prelude_not_request",
                    detail: "the client direction did not carry a request head".into(),
                    wire: Bytes::copy_from_slice(&view[..consumed.min(256)]),
                    sources,
                },
            )?;
            self.fail(context, Status::Malformed)?;
            return Ok(true);
        }
        let sets = dir.buffer.contributors(consumed);
        let (head_wire_bytes, dropped) = dir.buffer.take(consumed);
        Self::release_dir(dir, context, consumed)?;
        Self::release_dropped(dir, dropped, context)?;
        let (head, _) = http::parse_head(&head_wire_bytes)?
            .ok_or(Error::Invariant("previously parsed complete HTTP/1 head"))?;
        let head_wire = head_wire_bytes.len();
        let method = head.method().map(str::to_owned);
        let offer = match upgrade::upgrade_offer(&head) {
            Ok(offer) => offer,
            Err(detail) => {
                self.issue(
                    context,
                    Fault {
                        flow: self.dir_flow(Side::Client),
                        http2_stream_id: None,
                        scope: IssueScope::Connection,
                        certainty: Certainty::Confirmed,
                        status: Status::Unsupported,
                        code: "bad_upgrade_offer",
                        detail: detail.into(),
                        wire: head_wire_bytes,
                        sources: union_balanced(sets.clone())?,
                    },
                )?;
                None
            }
        };
        let mut msg = self.new_message(0, MessageKind::Request, context)?;
        self.charge_conn(context, head_wire)?;
        msg.charged += head_wire;
        msg.upgrade_head = Some(head.clone());
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
        let index = msg.index;
        if self
            .prelude
            .as_ref()
            .ok_or(Error::Invariant("prelude"))?
            .requests
            .len()
            >= context.limits.max_active_streams
        {
            let sources = union_balanced(std::mem::take(&mut msg.sets))?;
            self.drop_msg(msg, context)?;
            self.issue(
                context,
                Fault {
                    flow: self.dir_flow(Side::Client),
                    http2_stream_id: None,
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Limit,
                    code: "pending_requests",
                    detail: "pre-upgrade requests exceed the configured bound".into(),
                    wire: head.wire().clone(),
                    sources,
                },
            )?;
            self.fail(context, Status::Limit)?;
            return Ok(true);
        }
        self.charge_conn(context, resources::PENDING_OVERHEAD)?;
        let prelude = self.prelude.as_mut().ok_or(Error::Invariant("prelude"))?;
        prelude.requests.push_back(Pending {
            index,
            method: method.clone(),
            upgrade: offer.is_some(),
        });
        if let Some(settings) = offer {
            let charge = resources::OFFER_OVERHEAD + settings.capacity() * 24;
            self.charge_conn(context, charge)?;
            let prelude = self.prelude.as_mut().ok_or(Error::Invariant("prelude"))?;
            prelude.offers.insert(
                index,
                Offer {
                    settings,
                    msg: None,
                },
            );
        }
        let framing = match head.body(None) {
            Ok(framing) => framing,
            Err(error) => {
                let sources = union_balanced(std::mem::take(&mut msg.sets))?;
                self.drop_msg(msg, context)?;
                self.issue(
                    context,
                    Fault {
                        flow: self.dir_flow(Side::Client),
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
        let is_offer = self
            .prelude
            .as_ref()
            .is_some_and(|p| p.offers.contains_key(&index));
        if matches!(framing, http::Body::Chunked) {
            if let Err(error) = self.charge_conn(context, resources::PRELUDE_BODY_RESERVE) {
                self.drop_msg(msg, context)?;
                return Err(error);
            }
            self.prelude
                .as_mut()
                .ok_or(Error::Invariant("prelude"))?
                .body_charge[Side::Client] = resources::PRELUDE_BODY_RESERVE;
        }
        let decoder = BodyDecoder::new(framing, context.limits.max_body_bytes);
        if decoder.complete() {
            if is_offer {
                let prelude = self.prelude.as_mut().ok_or(Error::Invariant("prelude"))?;
                if let Some(offer) = prelude.offers.get_mut(&index) {
                    offer.msg = Some(msg);
                }
                if prelude.upgraded {
                    let offer = prelude
                        .offers
                        .remove(&index)
                        .ok_or(Error::Invariant("offer"))?;
                    self.complete_upgrade_request(offer, context)?;
                }
            } else {
                self.drop_msg(msg, context)?;
            }
        } else {
            let prelude = self.prelude.as_mut().ok_or(Error::Invariant("prelude"))?;
            prelude.client_body = Some(decoder);
            prelude.live_request = Some(msg);
        }
        Ok(true)
    }
}
