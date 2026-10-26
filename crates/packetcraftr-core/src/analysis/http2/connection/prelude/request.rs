// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::super::Error;
use super::super::super::buffer::union_balanced;
use super::super::super::model::{Header, IssueScope, MessageKind, Status};
use super::super::super::upgrade::{self, Offer, Pending};
use super::super::{ConnectionState, Context, Fault};
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::budget;
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
                dir.release_consumed(take, dropped, context)?;
                self.reject(
                    context,
                    Fault::new(
                        flow,
                        IssueScope::Connection,
                        Status::Malformed,
                        IssueCode::PreludeHead,
                        error.to_string(),
                    )
                    .evidence(wire, sources),
                )?;
                return Ok(true);
            }
        };
        if !matches!(head.start, StartLine::Request { .. }) {
            let flow = dir.flow.clone();
            let sets = dir.buffer.contributors(consumed.min(dir.buffer.len()));
            let (_, dropped) = dir.buffer.take(consumed.min(dir.buffer.len()));
            let sources = union_balanced(sets)?;
            dir.release_consumed(consumed, dropped, context)?;
            self.reject(
                context,
                Fault::new(
                    flow,
                    IssueScope::Connection,
                    Status::Malformed,
                    IssueCode::PreludeNotRequest,
                    "the client direction did not carry a request head",
                )
                .evidence(Bytes::copy_from_slice(&view[..consumed.min(256)]), sources),
            )?;
            return Ok(true);
        }
        let sets = dir.buffer.contributors(consumed);
        let (head_wire_bytes, dropped) = dir.buffer.take(consumed);
        dir.release_consumed(consumed, dropped, context)?;
        let (head, _) = http::parse_head(&head_wire_bytes)?
            .ok_or(Error::Invariant("previously parsed complete HTTP/1 head"))?;
        let head_wire = head_wire_bytes.len();
        let method = head.method().map(str::to_owned);
        let offer = match upgrade::upgrade_offer(&head) {
            Ok(offer) => offer,
            Err(detail) => {
                self.issue(
                    context,
                    Fault::new(
                        self.dir_flow(Side::Client),
                        IssueScope::Connection,
                        Status::Unsupported,
                        IssueCode::BadUpgradeOffer,
                        detail,
                    )
                    .evidence(head_wire_bytes, union_balanced(sets.clone())?),
                )?;
                None
            }
        };
        let mut msg = self.new_message(0, MessageKind::Request, context)?;
        context.charge(&mut msg.charge, head_wire)?;
        msg.upgrade_head = Some(head.clone());
        let header_charge = head
            .headers
            .iter()
            .map(|h| h.name.len() + h.value.len() + budget::HEADER_OVERHEAD)
            .sum::<usize>();
        context.charge(&mut msg.charge, header_charge)?;
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
            context.track(&mut msg.charge, &set)?;
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
            self.reject(
                context,
                Fault::new(
                    self.dir_flow(Side::Client),
                    IssueScope::Connection,
                    Status::Limit,
                    IssueCode::PendingRequests,
                    "pre-upgrade requests exceed the configured bound",
                )
                .evidence(head.wire().clone(), sources),
            )?;
            return Ok(true);
        }
        context.charge(&mut self.charge, budget::PENDING_OVERHEAD)?;
        let prelude = self.prelude.as_mut().ok_or(Error::Invariant("prelude"))?;
        prelude.requests.push_back(Pending {
            index,
            method: method.clone(),
            upgrade: offer.is_some(),
        });
        if let Some(settings) = offer {
            let charge = budget::OFFER_OVERHEAD + settings.capacity() * 24;
            context.charge(&mut self.charge, charge)?;
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
                self.reject(
                    context,
                    Fault::new(
                        self.dir_flow(Side::Client),
                        IssueScope::Connection,
                        Status::Malformed,
                        IssueCode::PreludeFraming,
                        error.to_string(),
                    )
                    .evidence(head.wire().clone(), sources),
                )?;
                return Ok(true);
            }
        };
        let is_offer = self
            .prelude
            .as_ref()
            .is_some_and(|p| p.offers.contains_key(&index));
        if matches!(framing, http::Body::Chunked) {
            let prelude = self.prelude.as_mut().ok_or(Error::Invariant("prelude"))?;
            if let Err(error) = context.charge(
                &mut prelude.body_charge[Side::Client],
                budget::PRELUDE_BODY_RESERVE,
            ) {
                self.drop_msg(msg, context)?;
                return Err(error);
            }
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
