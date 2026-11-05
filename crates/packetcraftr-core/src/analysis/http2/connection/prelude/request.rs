// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::super::Error;
use super::super::super::buffer::union_balanced;
use super::super::super::model::{IssueScope, MessageKind, Status};
use super::super::super::upgrade::{self, Offer, Pending};
use super::super::{ConnectionState, Context, Fault};
use super::{PreludeHead, UnexpectedHead, record_head};
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::budget;
use crate::analysis::http2::side::Side;
use crate::protocol::application::http::{self, BodyDecoder, StartLine};

impl ConnectionState {
    pub(super) fn client_prelude_step(&mut self, context: &mut Context<'_>) -> Result<bool, Error> {
        let (head, head_wire_bytes, sets) = match self.take_prelude_head(
            Side::Client,
            |start| matches!(start, StartLine::Request { .. }),
            UnexpectedHead::NOT_REQUEST,
            context,
        )? {
            PreludeHead::Incomplete => return Ok(false),
            PreludeHead::Rejected => return Ok(true),
            PreludeHead::Taken { head, wire, sets } => (head, wire, sets),
        };
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
        msg.upgrade_head = Some(head.clone());
        record_head(&mut msg, &head, head_wire, sets, context)?;
        let index = msg.index;
        if self
            .upgrade
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
        let prelude = self
            .upgrade
            .prelude
            .as_mut()
            .ok_or(Error::Invariant("prelude"))?;
        prelude.requests.push_back(Pending {
            index,
            method: method.clone(),
            upgrade: offer.is_some(),
        });
        if let Some(settings) = offer {
            let charge = budget::OFFER_OVERHEAD + settings.capacity() * 24;
            context.charge(&mut self.charge, charge)?;
            let prelude = self
                .upgrade
                .prelude
                .as_mut()
                .ok_or(Error::Invariant("prelude"))?;
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
            .upgrade
            .prelude
            .as_ref()
            .is_some_and(|p| p.offers.contains_key(&index));
        if matches!(framing, http::Body::Chunked) {
            let prelude = self
                .upgrade
                .prelude
                .as_mut()
                .ok_or(Error::Invariant("prelude"))?;
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
                let prelude = self
                    .upgrade
                    .prelude
                    .as_mut()
                    .ok_or(Error::Invariant("prelude"))?;
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
            let prelude = self
                .upgrade
                .prelude
                .as_mut()
                .ok_or(Error::Invariant("prelude"))?;
            prelude.client_body = Some(decoder);
            prelude.live_request = Some(msg);
        }
        Ok(true)
    }
}
