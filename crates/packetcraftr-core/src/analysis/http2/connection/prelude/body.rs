// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::super::Error;
use super::super::super::buffer::union_balanced;
use super::super::super::model::{Certainty, Header, IssueScope, Status};
use super::super::super::stream::{CLIENT, MessageBuilder};
use super::super::{ConnectionState, Context, Fault, resources};
use crate::analysis::application;
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
        side: usize,
        context: &mut Context<'_>,
    ) -> Result<BodyStep, Error> {
        let dir =
            self.dirs[side]
                .as_mut()
                .ok_or(Error::Application(application::Error::Sources {
                    number: self.number,
                }))?;
        let has_body = self.prelude.as_ref().is_some_and(|p| {
            if side == CLIENT {
                p.client_body.is_some()
            } else {
                p.server_body.is_some()
            }
        });
        if !has_body {
            return Ok(BodyStep::NotBody);
        }
        let prelude = self.prelude.as_mut().expect("prelude");
        let body = if side == CLIENT {
            prelude.client_body.as_mut().expect("body")
        } else {
            prelude.server_body.as_mut().expect("body")
        };
        let progress = match body.consume(dir.buffer.bytes()) {
            Ok(progress) => progress,
            Err(error) => {
                let flow = dir.flow.clone();
                let take = dir.buffer.len();
                let sets = dir.buffer.contributors(take);
                let (wire, dropped) = dir.buffer.take(take);
                let sources = union_balanced(sets)?;
                Self::release_dir(dir, context, take);
                Self::release_dropped(dir, dropped, context);
                let status = if matches!(error, http::Error::Limit(_)) {
                    Status::Limit
                } else {
                    Status::Malformed
                };
                self.issue(
                    context,
                    Fault {
                        flow,
                        http2_stream_id: None,
                        scope: IssueScope::Connection,
                        certainty: Certainty::Confirmed,
                        status,
                        code: "prelude_body",
                        detail: error.to_string().into(),
                        wire,
                        sources,
                    },
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
            let dropped = dir.buffer.discard(consumed);
            Self::release_dir(dir, context, consumed);
            Self::release_dropped(dir, dropped, context);
            let prelude = self.prelude.as_mut().expect("prelude");
            let msg_slot = if side == CLIENT {
                &mut prelude.live_request
            } else {
                &mut prelude.live_response
            };
            if let Some(msg) = msg_slot.as_mut() {
                msg.body_bytes = body_bytes;
                for set in sets {
                    let frames = set.frames().len();
                    let charge = resources::SET_OVERHEAD + frames * resources::SPAN_OVERHEAD;
                    self.charge_conn(context, charge)?;
                    context.charge_spans(frames)?;
                    let prelude = self.prelude.as_mut().expect("prelude");
                    let msg = if side == CLIENT {
                        prelude.live_request.as_mut().expect("request")
                    } else {
                        prelude.live_response.as_mut().expect("response")
                    };
                    msg.charged += charge;
                    msg.charged_spans += frames;
                    msg.sets.push(set);
                }
            }
        }
        if complete {
            let trailer_charge = trailers
                .iter()
                .map(|h| h.name.len() + h.value.len() + resources::HEADER_OVERHEAD)
                .sum::<usize>();
            let prelude = self.prelude.as_mut().expect("prelude");
            if side == CLIENT {
                prelude.client_body = None;
            } else {
                prelude.server_body = None;
            }
            let msg = if side == CLIENT {
                prelude.live_request.take()
            } else {
                prelude.live_response.take()
            };
            let step = match msg {
                Some(mut msg) => {
                    if !trailers.is_empty() {
                        self.charge_conn(context, trailer_charge)?;
                        msg.charged += trailer_charge;
                        msg.trailers = trailers;
                    }
                    BodyStep::Complete(Box::new(msg))
                }
                None => BodyStep::Progress,
            };
            let charge =
                std::mem::take(&mut self.prelude.as_mut().expect("prelude").body_charge[side]);
            self.release_conn(context, charge);
            return Ok(step);
        }
        Ok(BodyStep::Progress)
    }
}
