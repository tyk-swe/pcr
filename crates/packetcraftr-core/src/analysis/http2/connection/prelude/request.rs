// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Client HTTP/1.1 prelude request intake and h2c upgrade offers.

use super::super::super::buffer::union_balanced;
use super::super::super::model::{MessageKind, Status};
use super::super::super::upgrade::{self, Offer, Pending};
use super::super::{ActiveState, Context, Fault, Reporter, StepResult};
use super::{PreludeHead, UnexpectedHead, record_head};
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::side::Side;
use crate::protocol::application::http::StartLine;

impl ActiveState {
    pub(super) fn client_prelude_step(
        &mut self,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<bool> {
        let PreludeHead::Taken { head, wire, sets } = self.take_prelude_head(
            Side::Client,
            |start| matches!(start, StartLine::Request { .. }),
            UnexpectedHead::NOT_REQUEST,
            reporter,
            context,
        )?
        else {
            return Ok(false);
        };
        let head_wire = wire.len();
        let method = head.method().map(str::to_owned);
        let offer = match upgrade::upgrade_offer(&head) {
            Ok(offer) => offer,
            Err(detail) => {
                reporter.issue(
                    context,
                    Fault::connection(
                        self.directions.flow(Side::Client),
                        Status::Unsupported,
                        IssueCode::BadUpgradeOffer,
                        detail,
                    )
                    .with_evidence(wire, union_balanced(sets.clone())?),
                )?;
                None
            }
        };
        let mut msg = Self::new_message(0, MessageKind::Request, context)?;
        msg.upgrade_head = Some(head.clone());
        record_head(&mut msg, &head, head_wire, sets, context)?;
        let index = msg.index;
        let Some(prelude) = self.prelude.as_mut() else {
            context.release_all(&mut msg.charge)?;
            return Ok(true);
        };
        if prelude.requests.len() >= context.limits.max_active_streams {
            let sources = union_balanced(std::mem::take(&mut msg.sets))?;
            context.release_all(&mut msg.charge)?;
            return reporter.reject(
                context,
                Fault::connection(
                    self.directions.flow(Side::Client),
                    Status::Limit,
                    IssueCode::PendingRequests,
                    "pre-upgrade requests exceed the configured bound",
                )
                .with_evidence(head.wire().clone(), sources),
            );
        }
        prelude.push_request(
            Pending {
                index,
                method,
                upgrade: offer.is_some(),
            },
            context,
        )?;
        if let Some(settings) = offer {
            prelude.insert_offer(
                index,
                Offer {
                    settings,
                    msg: None,
                },
                context,
            )?;
        }
        self.attach_prelude_body(Side::Client, &head, None, msg, reporter, context)
    }
}
