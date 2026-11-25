// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Server HTTP/1.1 prelude responses, 101 Switching Protocols handoff, and EOF checks.

use super::super::super::Error;
use super::super::super::buffer::union_balanced;
use super::super::super::model::{Certainty, MessageKind, Status};
use super::super::super::upgrade;
use super::super::{ActiveState, Context, Fault, Reporter, StepResult};
use super::{PreludeHead, UnexpectedHead, UpgradeAcceptance, record_head};
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::budget;
use crate::analysis::http2::side::Side;
use crate::analysis::provenance::SourceSet;
use crate::protocol::application::http::{self, StartLine};
use bytes::Bytes;

impl ActiveState {
    pub(in super::super) fn report_unmatched_response_at_eof(
        &mut self,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let Some(prelude) = self.prelude.as_ref() else {
            return Ok(());
        };
        if !prelude.requests.is_empty() {
            return Ok(());
        }
        let Some(server) = self.directions.server.as_ref() else {
            return Ok(());
        };
        let need = server.buffer.len().min(http::MAX_HEADER_BYTES + 1);
        if need == 0 {
            return Ok(());
        }
        let uncertain = !self.clean_start
            || reporter.status != Status::Complete
            || !self.directions.client.buffer.is_empty()
            || prelude.sides[Side::Client].live_message.is_some();
        let scratch = need * 4 + budget::PRELUDE_HEADER_OVERHEAD;
        context.with_scratch(scratch, |context| {
            let Some(server) = self.directions.server.as_mut() else {
                return Ok(());
            };
            let view = Bytes::copy_from_slice(&server.buffer.bytes()[..need]);
            let Ok(Some((head, consumed))) = http::parse_head(&view) else {
                return Ok(());
            };
            if !matches!(head.start, StartLine::Response { .. }) {
                return Ok(());
            }
            let flow = server.flow.clone();
            let (wire, sets) = server.buffer.take(consumed, context)?;
            let (status, certainty) = if !uncertain {
                (Status::Malformed, Certainty::Confirmed)
            } else {
                (Status::Incomplete, Certainty::Indeterminate)
            };
            reporter.issue(
                context,
                Fault::connection(
                    flow,
                    status,
                    IssueCode::PreludeUnsolicitedResponse,
                    "capture ended without a request matching this HTTP/1 response",
                )
                .with_certainty(certainty)
                .with_evidence(wire, union_balanced(sets)?),
            )
        })
    }

    pub(super) fn server_prelude_step(
        &mut self,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<bool> {
        let unmatched = self
            .prelude
            .as_ref()
            .is_some_and(|prelude| prelude.requests.is_empty());
        let partial_request = !self.directions.client.buffer.is_empty();
        if unmatched && (!self.clean_start || partial_request) {
            // Capture order can expose a response before the request head is
            // complete. Keep its bytes and sources in the charged direction
            // buffer; the next client delivery pumps this direction again.
            return Ok(false);
        }
        let PreludeHead::Taken { head, wire, sets } = self.take_prelude_head(
            Side::Server,
            |start| matches!(start, StartLine::Response { .. }),
            UnexpectedHead::NOT_RESPONSE,
            reporter,
            context,
        )?
        else {
            return Ok(false);
        };
        let status = head.status().ok_or(Error::Invariant("response"))?;
        if status < 200
            && (head.values("content-length").next().is_some()
                || head.values("transfer-encoding").next().is_some())
        {
            return reporter.reject(
                context,
                Fault::connection(
                    self.directions.flow(Side::Server),
                    Status::Malformed,
                    IssueCode::PreludeFraming,
                    "informational responses cannot contain Content-Length or Transfer-Encoding",
                )
                .with_evidence(wire, union_balanced(sets)?),
            );
        }
        if status == 101 {
            return self.handle_101_response(head, wire, sets, reporter, context);
        }
        let Some(front_index) = self
            .prelude
            .as_ref()
            .and_then(|prelude| prelude.requests.front().map(|pending| pending.index))
        else {
            return reporter.reject(
                context,
                Fault::connection(
                    self.directions.flow(Side::Server),
                    Status::Malformed,
                    IssueCode::PreludeUnsolicitedResponse,
                    "HTTP/1 response has no pending request",
                )
                .with_certainty(if self.clean_start {
                    Certainty::Confirmed
                } else {
                    Certainty::Indeterminate
                })
                .with_evidence(wire, union_balanced(sets)?),
            );
        };
        let head_wire = wire.len();
        let mut msg = Self::new_message(0, MessageKind::Response, context)?;
        record_head(&mut msg, &head, head_wire, sets, context)?;
        msg.request = Some(front_index);
        if status < 200 {
            context.release_all(&mut msg.charge)?;
            return Ok(true);
        }
        let Some(pending) = self
            .prelude
            .as_mut()
            .and_then(|prelude| prelude.pop_request(context).transpose())
            .transpose()?
        else {
            context.release_all(&mut msg.charge)?;
            return Ok(true);
        };
        if pending.upgrade {
            self.decline_upgrade_offer(pending.index, reporter, context)?;
        }
        self.attach_prelude_body(
            Side::Server,
            &head,
            pending.method.as_deref(),
            msg,
            reporter,
            context,
        )
    }

    fn handle_101_response(
        &mut self,
        head: http::Head,
        wire: Bytes,
        sets: Vec<SourceSet>,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<bool> {
        let matched = self.prelude.as_ref().is_some_and(|prelude| {
            prelude.requests.front().is_some_and(|pending| {
                pending.upgrade && prelude.offers.contains_key(&pending.index)
            })
        });
        if !matched || !upgrade::accepts_upgrade(&head) {
            return reporter.reject(
                context,
                Fault::connection(
                    self.directions.flow(Side::Server),
                    Status::Unsupported,
                    IssueCode::Unexpected101,
                    "a 101 response does not match a pending h2c offer",
                )
                .with_evidence(wire, union_balanced(sets)?),
            );
        }
        let Some(pending) = self
            .prelude
            .as_mut()
            .and_then(|prelude| prelude.pop_request(context).transpose())
            .transpose()?
        else {
            return Ok(true);
        };
        self.accept_upgrade(
            UpgradeAcceptance {
                index: pending.index,
                head,
                head_wire: wire,
                sets,
                method: pending.method,
            },
            reporter,
            context,
        )?;
        Ok(true)
    }

    fn decline_upgrade_offer(
        &mut self,
        index: u64,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if let Some(mut offer) = self
            .prelude
            .as_mut()
            .and_then(|prelude| prelude.remove_offer(index, context).transpose())
            .transpose()?
            && let Some(held) = offer.msg.take()
        {
            self.refused_upgrade(held, reporter, context)?;
        }
        let live = self.prelude.as_mut().and_then(|prelude| {
            let slot = &mut prelude.sides[Side::Client];
            if slot
                .live_message
                .as_ref()
                .is_some_and(|msg| msg.index == index)
            {
                slot.live_message.take()
            } else {
                None
            }
        });
        if let Some(live) = live {
            self.refused_upgrade(live, reporter, context)?;
        }
        self.upgrade.refused = true;
        Ok(())
    }
}
