// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::super::Error;
use super::super::super::buffer::union_balanced;
use super::super::super::model::{Certainty, Header, IssueScope, MessageKind, Status};
use super::super::super::upgrade;
use super::super::{ConnectionState, Context, Fault, Phase};
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::budget;
use crate::analysis::http2::side::Side;
use crate::protocol::application::http::{self, BodyDecoder, StartLine};
use bytes::Bytes;

impl ConnectionState {
    pub(in super::super) fn report_unmatched_response_at_eof(
        &mut self,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if !matches!(self.phase, Phase::Prelude)
            || !self
                .upgrade
                .prelude
                .as_ref()
                .is_some_and(|p| p.requests.is_empty())
        {
            return Ok(());
        }
        let Some(dir) = self.directions.get(Side::Server) else {
            return Ok(());
        };
        let need = dir.buffer.len().min(http::MAX_HEADER_BYTES + 1);
        if need == 0 {
            return Ok(());
        }
        let uncertain = !self.clean_start
            || self.status != Status::Complete
            || self
                .directions
                .get(Side::Client)
                .is_some_and(|dir| !dir.buffer.is_empty())
            || self
                .upgrade
                .prelude
                .as_ref()
                .is_some_and(|p| p.live_request.is_some());
        let scratch = need * 4 + budget::PRELUDE_HEADER_OVERHEAD;
        context.reserve_scratch(scratch)?;
        let result = (|| {
            let dir = self
                .directions
                .get_mut(Side::Server)
                .ok_or(Error::Invariant("server"))?;
            let view = Bytes::copy_from_slice(&dir.buffer.bytes()[..need]);
            let Ok(Some((head, consumed))) = http::parse_head(&view) else {
                return Ok(());
            };
            if !matches!(head.start, StartLine::Response { .. }) {
                return Ok(());
            }
            let sets = dir.buffer.contributors(consumed);
            let (wire, dropped) = dir.buffer.take(consumed);
            dir.release_consumed(consumed, dropped, context)?;
            self.issue(
                context,
                Fault::new(
                    self.dir_flow(Side::Server),
                    IssueScope::Connection,
                    if !uncertain {
                        Status::Malformed
                    } else {
                        Status::Incomplete
                    },
                    IssueCode::PreludeUnsolicitedResponse,
                    "capture ended without a request matching this HTTP/1 response",
                )
                .certainty(if !uncertain {
                    Certainty::Confirmed
                } else {
                    Certainty::Indeterminate
                })
                .evidence(wire, union_balanced(sets)?),
            )
        })();
        context.release_scratch(scratch)?;
        result
    }

    pub(super) fn server_prelude_step(&mut self, context: &mut Context<'_>) -> Result<bool, Error> {
        let unmatched = self
            .upgrade
            .prelude
            .as_ref()
            .is_some_and(|p| p.requests.is_empty());
        let partial_request = self
            .directions
            .get(Side::Client)
            .is_some_and(|dir| !dir.buffer.is_empty());
        if unmatched && (!self.clean_start || partial_request) {
            // Capture order can expose a response before the request head is
            // complete. Keep its bytes and sources in the charged direction
            // buffer; the next client delivery pumps this direction again.
            return Ok(false);
        }
        let dir = self
            .directions
            .get_mut(Side::Server)
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
        if !matches!(head.start, StartLine::Response { .. }) {
            let flow = dir.flow.clone();
            let release_len = consumed.min(dir.buffer.len());
            let sets = dir.buffer.contributors(release_len);
            let (_, dropped) = dir.buffer.take(release_len);
            let sources = union_balanced(sets)?;
            dir.release_consumed(release_len, dropped, context)?;
            self.reject(
                context,
                Fault::new(
                    flow,
                    IssueScope::Connection,
                    Status::Malformed,
                    IssueCode::PreludeNotResponse,
                    "the server direction did not carry a response head",
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
        let status = head.status().ok_or(Error::Invariant("response"))?;
        let front = self.upgrade.prelude.as_mut().and_then(|p| {
            p.requests
                .front()
                .map(|p| (p.index, p.method.clone(), p.upgrade))
        });
        let matched = front.as_ref().is_some_and(|(index, _, upgrade)| {
            *upgrade
                && self
                    .upgrade
                    .prelude
                    .as_ref()
                    .is_some_and(|p| p.offers.contains_key(index))
        });
        if status < 200
            && (head.values("content-length").next().is_some()
                || head.values("transfer-encoding").next().is_some())
        {
            self.reject(
                context,
                Fault::new(
                    self.dir_flow(Side::Server),
                    IssueScope::Connection,
                    Status::Malformed,
                    IssueCode::PreludeFraming,
                    "informational responses cannot contain Content-Length or Transfer-Encoding",
                )
                .evidence(head_wire_bytes, union_balanced(sets)?),
            )?;
            return Ok(true);
        }
        if status == 101 {
            if matched && upgrade::accepts_upgrade(&head) {
                let (index, method, _) = front.clone().ok_or(Error::Invariant("front"))?;
                let prelude = self
                    .upgrade
                    .prelude
                    .as_mut()
                    .ok_or(Error::Invariant("prelude"))?;
                prelude.requests.pop_front();
                context.release(&mut self.charge, budget::PENDING_OVERHEAD)?;
                self.accept_upgrade(index, head, head_wire_bytes, sets, method, context)?;
                return Ok(true);
            }
            self.reject(
                context,
                Fault::new(
                    self.dir_flow(Side::Server),
                    IssueScope::Connection,
                    Status::Unsupported,
                    IssueCode::Unexpected101,
                    "a 101 response does not match a pending h2c offer",
                )
                .evidence(head_wire_bytes, union_balanced(sets)?),
            )?;
            return Ok(true);
        }
        if front.is_none() {
            self.reject(
                context,
                Fault::new(
                    self.dir_flow(Side::Server),
                    IssueScope::Connection,
                    Status::Malformed,
                    IssueCode::PreludeUnsolicitedResponse,
                    "HTTP/1 response has no pending request",
                )
                .certainty(if self.clean_start {
                    Certainty::Confirmed
                } else {
                    Certainty::Indeterminate
                })
                .evidence(head_wire_bytes, union_balanced(sets)?),
            )?;
            return Ok(true);
        }
        let mut msg = self.new_message(0, MessageKind::Response, context)?;
        context.charge(&mut msg.charge, head_wire)?;
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
        if let Some((index, ..)) = front {
            msg.request = Some(index);
        }
        let informational = status < 200;
        if informational {
            self.drop_msg(msg, context)?;
            return Ok(true);
        }
        let had_front = front.is_some();
        let (front_index, method, was_upgrade) = front.unwrap_or((0, None, false));
        if had_front {
            let prelude = self
                .upgrade
                .prelude
                .as_mut()
                .ok_or(Error::Invariant("prelude"))?;
            prelude.requests.pop_front();
            context.release(&mut self.charge, budget::PENDING_OVERHEAD)?;
        }
        if was_upgrade {
            if let Some(mut offer) = self
                .upgrade
                .prelude
                .as_mut()
                .and_then(|prelude| prelude.offers.remove(&front_index))
            {
                context.release(
                    &mut self.charge,
                    budget::OFFER_OVERHEAD + offer.settings.capacity() * 24,
                )?;
                if let Some(held) = offer.msg.take() {
                    self.refused_upgrade(held, context)?;
                }
            }
            let live = self.upgrade.prelude.as_mut().and_then(|prelude| {
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
            self.upgrade.refused = true;
        }
        let framing = match head.body(method.as_deref()) {
            Ok(framing) => framing,
            Err(error) => {
                let sources = union_balanced(std::mem::take(&mut msg.sets))?;
                self.drop_msg(msg, context)?;
                self.reject(
                    context,
                    Fault::new(
                        self.dir_flow(Side::Server),
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
        if matches!(framing, http::Body::Chunked) {
            let prelude = self
                .upgrade
                .prelude
                .as_mut()
                .ok_or(Error::Invariant("prelude"))?;
            if let Err(error) = context.charge(
                &mut prelude.body_charge[Side::Server],
                budget::PRELUDE_BODY_RESERVE,
            ) {
                self.drop_msg(msg, context)?;
                return Err(error);
            }
        }
        let decoder = BodyDecoder::new(framing, context.limits.max_body_bytes);
        if decoder.complete() {
            self.drop_msg(msg, context)?;
        } else {
            let prelude = self
                .upgrade
                .prelude
                .as_mut()
                .ok_or(Error::Invariant("prelude"))?;
            prelude.server_body = Some(decoder);
            prelude.live_response = Some(msg);
        }
        Ok(true)
    }
}
