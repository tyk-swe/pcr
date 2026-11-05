// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod body;
mod request;
mod response;

use crate::analysis::http2::IssueCode;
use crate::analysis::http2::budget;
use body::BodyStep;

use super::super::Error;
use super::super::buffer::union_balanced;
use super::super::model::{Header, IssueScope, Startup, Status};
use super::super::stream::{MessageBuilder, StreamState};
use super::super::upgrade::Offer;
use super::{ConnectionState, Context, DirectionPhase, Fault, Phase};
use crate::analysis::http2::side::Side;
use crate::analysis::provenance::SourceSet;
use crate::protocol::application::http;
use bytes::Bytes;

struct UnexpectedHead {
    code: IssueCode,
    detail: &'static str,
}

impl UnexpectedHead {
    const NOT_REQUEST: Self = Self {
        code: IssueCode::PreludeNotRequest,
        detail: "the client direction did not carry a request head",
    };
    const NOT_RESPONSE: Self = Self {
        code: IssueCode::PreludeNotResponse,
        detail: "the server direction did not carry a response head",
    };
}

enum PreludeHead {
    Incomplete,
    Rejected,
    Taken {
        head: http::Head,
        wire: Bytes,
        sets: Vec<SourceSet>,
    },
}

fn record_head(
    msg: &mut MessageBuilder,
    head: &http::Head,
    head_wire: usize,
    sets: Vec<SourceSet>,
    context: &mut Context<'_>,
) -> Result<(), Error> {
    context.charge(&mut msg.charge, head_wire)?;
    let header_charge = head
        .headers
        .iter()
        .map(|h| h.name.len() + h.value.len() + budget::HEADER_OVERHEAD)
        .sum::<usize>();
    context.charge(&mut msg.charge, header_charge)?;
    msg.headers = head
        .headers
        .iter()
        .map(|header| Header {
            name: Bytes::copy_from_slice(header.name.as_bytes()),
            value: header.value.clone(),
            never_indexed: false,
        })
        .collect();
    for set in sets {
        context.track(&mut msg.charge, &set)?;
        msg.sets.push(set);
    }
    Ok(())
}

impl ConnectionState {
    fn take_prelude_head(
        &mut self,
        side: Side,
        expected: fn(&http::StartLine) -> bool,
        unexpected: UnexpectedHead,
        context: &mut Context<'_>,
    ) -> Result<PreludeHead, Error> {
        let dir = self
            .directions
            .get_mut(side)
            .ok_or(Error::Invariant("direction not found"))?;
        let need = dir.buffer.len().min(http::MAX_HEADER_BYTES + 1);
        let view = Bytes::copy_from_slice(&dir.buffer.bytes()[..need]);
        let (head, consumed) = match http::parse_head(&view) {
            Ok(Some(found)) => found,
            Ok(None) => return Ok(PreludeHead::Incomplete),
            Err(error) => {
                let flow = dir.flow.clone();
                let take = dir.buffer.len();
                let (wire, sets) = dir.buffer.take(take, context)?;
                let sources = union_balanced(sets)?;
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
                return Ok(PreludeHead::Rejected);
            }
        };
        if !expected(&head.start) {
            let flow = dir.flow.clone();
            let sets = dir
                .buffer
                .consume(consumed.min(dir.buffer.len()), context)?;
            let sources = union_balanced(sets)?;
            self.reject(
                context,
                Fault::new(
                    flow,
                    IssueScope::Connection,
                    Status::Malformed,
                    unexpected.code,
                    unexpected.detail,
                )
                .evidence(Bytes::copy_from_slice(&view[..consumed.min(256)]), sources),
            )?;
            return Ok(PreludeHead::Rejected);
        }
        let (wire, sets) = dir.buffer.take(consumed, context)?;
        let (head, _) = http::parse_head(&wire)?
            .ok_or(Error::Invariant("previously parsed complete HTTP/1 head"))?;
        Ok(PreludeHead::Taken { head, wire, sets })
    }

    pub(crate) fn prelude_step(
        &mut self,
        side: Side,
        context: &mut Context<'_>,
    ) -> Result<bool, Error> {
        let body_active = self.upgrade.prelude.as_ref().is_some_and(|prelude| {
            if side == Side::Client {
                prelude.client_body.is_some()
            } else {
                prelude.server_body.is_some()
            }
        });
        let buffered = self.directions.get(side).map_or(0, |dir| dir.buffer.len());
        let scratch = if body_active || buffered == 0 {
            0
        } else {
            buffered.min(http::MAX_HEADER_BYTES + 1) * 4 + budget::PRELUDE_HEADER_OVERHEAD
        };
        context.reserve_scratch(scratch)?;
        let result = self.prelude_step_inner(side, context);
        context.release_scratch(scratch)?;
        result
    }

    fn prelude_step_inner(&mut self, side: Side, context: &mut Context<'_>) -> Result<bool, Error> {
        match self.prelude_body_step(side, context)? {
            BodyStep::NotBody => {}
            BodyStep::Progress => return Ok(true),
            BodyStep::Stalled => return Ok(false),
            BodyStep::Complete(msg) => return self.body_complete(side, *msg, context),
        }
        if side == Side::Client {
            self.client_prelude_step(context)
        } else {
            self.server_prelude_step(context)
        }
    }

    fn drop_msg(
        &mut self,
        mut msg: MessageBuilder,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        context.release_all(&mut msg.charge)
    }

    fn refused_upgrade(
        &mut self,
        mut msg: MessageBuilder,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let head = msg
            .upgrade_head
            .take()
            .ok_or(Error::Invariant("upgrade request head"))?;
        let sources = union_balanced(std::mem::take(&mut msg.sets))?;
        self.drop_msg(msg, context)?;
        self.issue(
            context,
            // A refusal is a complete HTTP/1 exchange, not an HTTP/2 error.
            // EOF classifies the connection as unsupported if no retry succeeds.
            Fault::new(
                self.dir_flow(Side::Client),
                IssueScope::Connection,
                Status::Complete,
                IssueCode::RefusedUpgrade,
                "the server declined this h2c upgrade request",
            )
            .evidence(head.wire().clone(), sources),
        )
    }

    fn body_complete(
        &mut self,
        side: Side,
        msg: MessageBuilder,
        context: &mut Context<'_>,
    ) -> Result<bool, Error> {
        if side == Side::Server {
            self.drop_msg(msg, context)?;
            return Ok(true);
        }
        let Some(prelude) = self.upgrade.prelude.as_mut() else {
            self.drop_msg(msg, context)?;
            return Ok(true);
        };
        let index = msg.index;
        if let Some(offer) = prelude.offers.get_mut(&index) {
            offer.msg = Some(msg);
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
        Ok(true)
    }

    fn complete_upgrade_request(
        &mut self,
        offer: Offer,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        context.release(
            &mut self.charge,
            budget::OFFER_OVERHEAD + offer.settings.capacity() * 24,
        )?;
        if let Some(mut msg) = offer.msg {
            msg.stream_id = 1;
            self.emit_message(Side::Client, msg, Status::Complete, context)?;
        }
        self.end_side(Side::Client, 1, Status::Complete, context)?;
        if let Some(dir) = self.directions.get_mut(Side::Client) {
            dir.phase = DirectionPhase::Preface;
        }
        self.phase = Phase::H2;
        self.release_prelude(context)?;
        Ok(())
    }

    fn accept_upgrade(
        &mut self,
        index: u64,
        head: http::Head,
        head_wire: Bytes,
        sets: Vec<crate::analysis::provenance::SourceSet>,
        method: Option<String>,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let sources = union_balanced(sets)?;
        let mut prelude = self
            .upgrade
            .prelude
            .take()
            .ok_or(Error::Invariant("prelude"))?;
        let Some(mut offer) = prelude.offers.remove(&index) else {
            self.upgrade.prelude = Some(prelude);
            return Ok(());
        };
        context.release(
            &mut self.charge,
            budget::OFFER_OVERHEAD + offer.settings.capacity() * 24,
        )?;
        prelude.upgraded = true;
        let upgrade_charge = head_wire.len()
            + budget::SET_OVERHEAD
            + sources.as_ref().map_or(0, |s| s.frames().len()) * budget::SPAN_OVERHEAD
            + offer.settings.len() * 8
            + budget::OFFER_OVERHEAD;
        context.charge(&mut self.upgrade.charge, upgrade_charge)?;
        self.upgrade.response = Some(head);
        self.upgrade.sources = sources;
        let applied = {
            let direction = &mut self.control.settings[Side::Client];
            let applied = direction.apply(&offer.settings, false);
            // Upgrade header values do not satisfy the mandatory wire preface.
            direction.seen = false;
            direction.acknowledged = direction.advertised;
            applied
        };
        let invalid = !applied.issues.is_empty();
        let request_evidence = if invalid {
            let msg = offer.msg.as_ref().or(prelude.live_request.as_ref());
            msg.map(|msg| {
                Ok::<_, Error>((
                    msg.upgrade_head
                        .as_ref()
                        .ok_or(Error::Invariant("upgrade request head"))?
                        .wire()
                        .clone(),
                    union_balanced(msg.sets.clone())?,
                ))
            })
            .transpose()?
        } else {
            None
        };
        for issue in applied.issues {
            self.issue(
                context,
                Fault::new(
                    self.dir_flow(Side::Client),
                    IssueScope::Connection,
                    Status::Malformed,
                    issue.code,
                    issue.detail,
                )
                .evidence(
                    request_evidence
                        .as_ref()
                        .map_or_else(|| head_wire.clone(), |(wire, _)| wire.clone()),
                    request_evidence.as_ref().map_or_else(
                        || self.upgrade.sources.clone(),
                        |(_, sources)| sources.clone(),
                    ),
                ),
            )?;
        }
        if invalid {
            if let Some(msg) = offer.msg.take() {
                self.drop_msg(msg, context)?;
            }
            self.upgrade.prelude = Some(prelude);
            self.fail(context, Status::Malformed)?;
            return Ok(());
        }
        if let Some(dir) = self.directions.get_mut(Side::Server)
            && let Some(decoder) = dir.decoder.as_mut()
        {
            if let Some(min) = applied.pending.minimum_table_size {
                decoder.acknowledge_table_size(min)?;
            }
            decoder.acknowledge_table_size(applied.pending.final_values.header_table_size)?;
        }
        self.decoder_sync(Side::Server, context)?;
        for stream in self.streams.open.values_mut() {
            context.check_deadline()?;
            stream.send_window[Side::Server] += applied.pending.window_delta;
        }
        self.startup = Startup::H2c;
        self.upgrade.refused = false;
        self.streams.max_initiated[Side::Client] = 1;
        context.charge(&mut self.charge, budget::STREAM_OVERHEAD)?;
        let windows = self.initial_windows();
        let mut stream = StreamState::open(Side::Client, windows);
        stream.request = Some(index);
        stream.method = method.map(Bytes::from);
        let request_done = offer.msg.is_some() || prelude.live_request.is_none();
        stream.ended[Side::Client] = request_done;
        context.check_streams()?;
        self.streams.admitted += 1;
        self.streams.open.insert(1, stream);
        self.streams.active[Side::Client] += 1;
        if let Some(dir) = self.directions.get_mut(Side::Server) {
            dir.phase = DirectionPhase::Frames;
        }
        if request_done {
            if let Some(mut msg) = offer.msg.take() {
                msg.stream_id = 1;
                self.emit_message(Side::Client, msg, Status::Complete, context)?;
            }
            if let Some(dir) = self.directions.get_mut(Side::Client) {
                dir.phase = DirectionPhase::Preface;
            }
            self.phase = Phase::H2;
            self.upgrade.prelude = Some(prelude);
            self.release_prelude(context)?;
        } else {
            context.charge(&mut self.charge, budget::OFFER_OVERHEAD)?;
            prelude.offers.insert(
                index,
                Offer {
                    settings: Vec::new(),
                    msg: offer.msg.take(),
                },
            );
            self.upgrade.prelude = Some(prelude);
        }
        Ok(())
    }
}
