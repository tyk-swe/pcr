// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::super::Error;
use super::super::super::buffer::union_balanced;
use super::super::super::model::{Header, IssueScope, Status};
use super::super::super::stream::MessageBuilder;
use super::super::{ConnectionState, Context, Fault};
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::budget;
use crate::analysis::http2::side::Side;
use crate::protocol::application::http;
use bytes::Bytes;

pub(super) enum BodyStep {
    NotBody,
    Progress,
    Stalled,
    Complete(Box<MessageBuilder>),
}

impl ConnectionState {
    pub(super) fn prelude_body_step(
        &mut self,
        side: Side,
        context: &mut Context<'_>,
    ) -> Result<BodyStep, Error> {
        let dir = self.dirs[side]
            .as_mut()
            .ok_or(Error::Invariant("direction not found"))?;
        let has_body = self.prelude.as_ref().is_some_and(|p| {
            if side == Side::Client {
                p.client_body.is_some()
            } else {
                p.server_body.is_some()
            }
        });
        if !has_body {
            return Ok(BodyStep::NotBody);
        }
        let prelude = self.prelude.as_mut().ok_or(Error::Invariant("prelude"))?;
        let body = if side == Side::Client {
            prelude
                .client_body
                .as_mut()
                .ok_or(Error::Invariant("body"))?
        } else {
            prelude
                .server_body
                .as_mut()
                .ok_or(Error::Invariant("body"))?
        };
        let progress = match body.consume(dir.buffer.bytes()) {
            Ok(progress) => progress,
            Err(error) => {
                let flow = dir.flow.clone();
                let take = dir.buffer.len();
                let sets = dir.buffer.contributors(take);
                let (wire, dropped) = dir.buffer.take(take);
                let sources = union_balanced(sets)?;
                dir.release_consumed(take, dropped, context)?;
                let status = if matches!(error, http::Error::Limit(_)) {
                    Status::Limit
                } else {
                    Status::Malformed
                };
                self.issue(
                    context,
                    Fault::new(
                        flow,
                        IssueScope::Connection,
                        status,
                        IssueCode::PreludeBody,
                        error.to_string(),
                    )
                    .evidence(wire, sources),
                )?;
                self.fail(context, status)?;
                return Ok(BodyStep::Progress);
            }
        };
        if progress.consumed == 0 && !progress.complete {
            return Ok(BodyStep::Stalled);
        }
        let consumed = progress.consumed;
        let complete = progress.complete;
        let body_bytes = body.body_bytes();
        let trailers: Vec<Header> = if complete {
            body.trailers()
                .iter()
                .map(|header| Header {
                    name: Bytes::copy_from_slice(header.name.as_bytes()),
                    value: header.value.clone(),
                    never_indexed: false,
                })
                .collect()
        } else {
            Vec::new()
        };
        if consumed > 0 {
            let sets = dir.buffer.contributors(consumed);
            let dropped = dir.buffer.consume(consumed);
            dir.release_consumed(consumed, dropped, context)?;
            let prelude = self.prelude.as_mut().ok_or(Error::Invariant("prelude"))?;
            let msg_slot = if side == Side::Client {
                &mut prelude.live_request
            } else {
                &mut prelude.live_response
            };
            if let Some(msg) = msg_slot.as_mut() {
                msg.body_bytes = body_bytes;
                for set in sets {
                    context.track(&mut msg.charge, &set)?;
                    msg.sets.push(set);
                }
            }
        }
        if complete {
            let trailer_charge = trailers
                .iter()
                .map(|h| h.name.len() + h.value.len() + budget::HEADER_OVERHEAD)
                .sum::<usize>();
            let prelude = self.prelude.as_mut().ok_or(Error::Invariant("prelude"))?;
            if side == Side::Client {
                prelude.client_body = None;
            } else {
                prelude.server_body = None;
            }
            let msg = if side == Side::Client {
                prelude.live_request.take()
            } else {
                prelude.live_response.take()
            };
            let step = match msg {
                Some(mut msg) => {
                    if !trailers.is_empty() {
                        context.charge(&mut msg.charge, trailer_charge)?;
                        msg.trailers = trailers;
                    }
                    BodyStep::Complete(Box::new(msg))
                }
                None => BodyStep::Progress,
            };
            let prelude = self.prelude.as_mut().ok_or(Error::Invariant("prelude"))?;
            context.release_all(&mut prelude.body_charge[side])?;
            return Ok(step);
        }
        Ok(BodyStep::Progress)
    }
}
