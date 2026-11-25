// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! HTTP/1.1 prelude head/body stepping and h2c upgrade handoff.

mod request;
mod response;

use super::super::Error;
use super::super::buffer::union_balanced;
use super::super::model::{Header, Startup, Status};
use super::super::stream::{MessageBuilder, StreamState, header_charge};
use super::super::upgrade::Offer;
use super::{ActiveState, Context, DirectionPhase, Fault, Reporter, StepAbort, StepResult};
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::budget;
use crate::analysis::http2::side::Side;
use crate::analysis::provenance::SourceSet;
use crate::protocol::application::http::{self, BodyDecoder};
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

pub(super) struct UpgradeAcceptance {
    pub index: u64,
    pub head: http::Head,
    pub head_wire: Bytes,
    pub sets: Vec<SourceSet>,
    pub method: Option<String>,
}

enum PreludeHead {
    Incomplete,
    Taken {
        head: http::Head,
        wire: Bytes,
        sets: Vec<SourceSet>,
    },
}

enum BodyStep {
    NotBody,
    Progress,
    Stalled,
    Complete(Box<MessageBuilder>),
}

fn record_head(
    msg: &mut MessageBuilder,
    head: &http::Head,
    head_wire: usize,
    sets: Vec<SourceSet>,
    context: &mut Context<'_>,
) -> Result<(), Error> {
    context.charge(&mut msg.charge, head_wire)?;
    let headers: Vec<Header> = head
        .headers
        .iter()
        .map(|header| Header {
            name: Bytes::copy_from_slice(header.name.as_bytes()),
            value: header.value.clone(),
            never_indexed: false,
        })
        .collect();
    context.charge(&mut msg.charge, header_charge(&headers))?;
    msg.headers = headers;
    for set in sets {
        context.track(&mut msg.charge, &set)?;
        msg.sets.push(set);
    }
    Ok(())
}

impl ActiveState {
    fn take_prelude_head(
        &mut self,
        side: Side,
        expected: fn(&http::StartLine) -> bool,
        unexpected: UnexpectedHead,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<PreludeHead> {
        let Some(dir) = self.directions.get_mut(side) else {
            return Ok(PreludeHead::Incomplete);
        };
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
                return reporter.reject(
                    context,
                    Fault::connection(
                        flow,
                        Status::Malformed,
                        IssueCode::PreludeHead,
                        error.to_string(),
                    )
                    .with_evidence(wire, sources),
                );
            }
        };
        if !expected(&head.start) {
            let flow = dir.flow.clone();
            let sets = dir
                .buffer
                .consume(consumed.min(dir.buffer.len()), context)?;
            let sources = union_balanced(sets)?;
            return reporter.reject(
                context,
                Fault::connection(flow, Status::Malformed, unexpected.code, unexpected.detail)
                    .with_evidence(Bytes::copy_from_slice(&view[..consumed.min(256)]), sources),
            );
        }
        let sets = dir.buffer.consume(consumed, context)?;
        let wire = view.slice(..consumed);
        Ok(PreludeHead::Taken { head, wire, sets })
    }

    pub(crate) fn prelude_step(
        &mut self,
        side: Side,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<bool> {
        let body_active = self
            .prelude
            .as_ref()
            .is_some_and(|prelude| prelude.sides[side].body.is_some());
        let buffered = self.directions.get(side).map_or(0, |dir| dir.buffer.len());
        let scratch = if body_active || buffered == 0 {
            0
        } else {
            buffered.min(http::MAX_HEADER_BYTES + 1) * 4 + budget::PRELUDE_HEADER_OVERHEAD
        };
        context.with_scratch(scratch, |context| {
            self.prelude_step_inner(side, reporter, context)
        })
    }

    fn prelude_step_inner(
        &mut self,
        side: Side,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<bool> {
        match self.prelude_body_step(side, reporter, context)? {
            BodyStep::NotBody => {}
            BodyStep::Progress => return Ok(true),
            BodyStep::Stalled => return Ok(false),
            BodyStep::Complete(msg) => return self.body_complete(side, *msg, reporter, context),
        }
        match side {
            Side::Client => self.client_prelude_step(reporter, context),
            Side::Server => self.server_prelude_step(reporter, context),
        }
    }

    fn prelude_body_step(
        &mut self,
        side: Side,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<BodyStep> {
        let (Some(dir), Some(prelude)) = (self.directions.get_mut(side), self.prelude.as_mut())
        else {
            return Ok(BodyStep::NotBody);
        };
        let slot = &mut prelude.sides[side];
        let Some(body) = slot.body.as_mut() else {
            return Ok(BodyStep::NotBody);
        };
        let progress = match body.consume(dir.buffer.bytes()) {
            Ok(progress) => progress,
            Err(error) => {
                let flow = dir.flow.clone();
                let take = dir.buffer.len();
                let (wire, sets) = dir.buffer.take(take, context)?;
                let sources = union_balanced(sets)?;
                let status = if matches!(error, http::Error::Limit(_)) {
                    Status::Limit
                } else {
                    Status::Malformed
                };
                return reporter.reject(
                    context,
                    Fault::connection(flow, status, IssueCode::PreludeBody, error.to_string())
                        .with_evidence(wire, sources),
                );
            }
        };
        if progress.consumed == 0 && !progress.complete {
            return Ok(BodyStep::Stalled);
        }
        let body_bytes = body.body_bytes();
        let trailers: Vec<Header> = if progress.complete {
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
        if progress.consumed > 0 {
            let sets = dir.buffer.consume(progress.consumed, context)?;
            if let Some(msg) = slot.live_message.as_mut() {
                msg.body_bytes = body_bytes;
                for set in sets {
                    context.track(&mut msg.charge, &set)?;
                    msg.sets.push(set);
                }
            }
        }
        if !progress.complete {
            return Ok(BodyStep::Progress);
        }
        slot.body = None;
        context.release_all(&mut slot.body_charge)?;
        let Some(mut msg) = slot.live_message.take() else {
            return Ok(BodyStep::Progress);
        };
        if !trailers.is_empty() {
            context.charge(&mut msg.charge, header_charge(&trailers))?;
            msg.trailers = trailers;
        }
        Ok(BodyStep::Complete(Box::new(msg)))
    }

    fn attach_prelude_body(
        &mut self,
        side: Side,
        head: &http::Head,
        request_method: Option<&str>,
        mut msg: MessageBuilder,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<bool> {
        let framing = match head.body(request_method) {
            Ok(framing) => framing,
            Err(error) => {
                let sources = union_balanced(std::mem::take(&mut msg.sets))?;
                context.release_all(&mut msg.charge)?;
                return reporter.reject(
                    context,
                    Fault::connection(
                        self.directions.flow(side),
                        Status::Malformed,
                        IssueCode::PreludeFraming,
                        error.to_string(),
                    )
                    .with_evidence(head.wire().clone(), sources),
                );
            }
        };
        if matches!(framing, http::Body::Chunked)
            && let Some(prelude) = self.prelude.as_mut()
            && let Err(error) = context.charge(
                &mut prelude.sides[side].body_charge,
                budget::PRELUDE_BODY_RESERVE,
            )
        {
            context.release_all(&mut msg.charge)?;
            return Err(error.into());
        }
        let decoder = BodyDecoder::new(framing, context.limits.max_body_bytes);
        if decoder.complete() {
            return self.body_complete(side, msg, reporter, context);
        }
        if let Some(prelude) = self.prelude.as_mut() {
            let slot = &mut prelude.sides[side];
            slot.body = Some(decoder);
            slot.live_message = Some(msg);
        } else {
            context.release_all(&mut msg.charge)?;
        }
        Ok(true)
    }

    fn refused_upgrade(
        &mut self,
        mut msg: MessageBuilder,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let head = msg
            .upgrade_head
            .take()
            .ok_or(Error::Invariant("upgrade request head"))?;
        let sources = union_balanced(std::mem::take(&mut msg.sets))?;
        context.release_all(&mut msg.charge)?;
        reporter.issue(
            context,
            // A refusal is a complete HTTP/1 exchange, not an HTTP/2 error.
            // EOF classifies the connection as unsupported if no retry succeeds.
            Fault::connection(
                self.directions.flow(Side::Client),
                Status::Complete,
                IssueCode::RefusedUpgrade,
                "the server declined this h2c upgrade request",
            )
            .with_evidence(head.wire().clone(), sources),
        )
    }

    fn body_complete(
        &mut self,
        side: Side,
        mut msg: MessageBuilder,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<bool> {
        if side == Side::Server {
            context.release_all(&mut msg.charge)?;
            return Ok(true);
        }
        let Some(prelude) = self.prelude.as_mut() else {
            context.release_all(&mut msg.charge)?;
            return Ok(true);
        };
        let index = msg.index;
        let Some(offer) = prelude.offers.get_mut(&index) else {
            context.release_all(&mut msg.charge)?;
            return Ok(true);
        };
        offer.msg = Some(msg);
        if prelude.upgraded
            && let Some(offer) = prelude.remove_offer(index, context)?
        {
            self.complete_upgrade_request(offer, reporter, context)?;
        }
        Ok(true)
    }

    fn complete_upgrade_request(
        &mut self,
        offer: Offer,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        if let Some(mut msg) = offer.msg {
            msg.stream_id = 1;
            self.emit_message(Side::Client, msg, Status::Complete, reporter, context)?;
        }
        self.end_side(Side::Client, 1, Status::Complete, reporter, context)?;
        self.directions.client.phase = DirectionPhase::Preface;
        self.release_prelude(context)?;
        Ok(())
    }

    fn accept_upgrade(
        &mut self,
        acceptance: UpgradeAcceptance,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        let UpgradeAcceptance {
            index,
            head,
            head_wire,
            sets,
            method,
        } = acceptance;
        let sources = union_balanced(sets)?;
        let Some(mut offer) = self
            .prelude
            .as_mut()
            .and_then(|prelude| prelude.remove_offer(index, context).transpose())
            .transpose()?
        else {
            return Ok(());
        };
        if let Some(prelude) = self.prelude.as_mut() {
            prelude.upgraded = true;
        }
        let upgrade_charge = head_wire.len()
            + sources
                .as_ref()
                .map_or(budget::SET_OVERHEAD, budget::set_cost)
            + offer.settings.len() * 8
            + budget::OFFER_OVERHEAD;
        context.charge(&mut self.upgrade.charge, upgrade_charge)?;
        self.upgrade.response = Some(head);
        self.upgrade.sources = sources;

        let applied = self.apply_upgrade_settings(&offer.settings);
        if !applied.issues.is_empty() {
            self.report_invalid_upgrade_settings(
                &mut offer,
                &head_wire,
                applied.issues,
                reporter,
                context,
            )?;
            return Err(StepAbort::ConnectionFailed(Status::Malformed));
        }
        self.sync_upgrade_server_decoder(&applied.pending, context)?;
        for (_, stream) in self.streams.open_iter_mut() {
            context.check_deadline()?;
            stream.send_window[Side::Server] += applied.pending.window_delta;
        }
        self.open_upgraded_stream_one(index, method, offer, reporter, context)
    }

    fn apply_upgrade_settings(
        &mut self,
        settings: &[crate::protocol::application::http2::Setting],
    ) -> super::super::settings::Applied {
        let direction = &mut self.control.settings[Side::Client];
        let applied = direction.apply(settings, false);
        // Upgrade header values do not satisfy the mandatory wire preface.
        direction.seen = false;
        direction.acknowledged = direction.advertised;
        applied
    }

    fn report_invalid_upgrade_settings(
        &mut self,
        offer: &mut Offer,
        head_wire: &Bytes,
        issues: Vec<super::super::settings::SettingIssue>,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let live_request = self
            .prelude
            .as_ref()
            .and_then(|prelude| prelude.sides[Side::Client].live_message.as_ref());
        let request_evidence = offer
            .msg
            .as_ref()
            .or(live_request)
            .map(|msg| {
                Ok::<_, Error>((
                    msg.upgrade_head
                        .as_ref()
                        .ok_or(Error::Invariant("upgrade request head"))?
                        .wire()
                        .clone(),
                    union_balanced(msg.sets.clone())?,
                ))
            })
            .transpose()?;
        for issue in issues {
            let (wire, sources) = match &request_evidence {
                Some((wire, sources)) => (wire.clone(), sources.clone()),
                None => (head_wire.clone(), self.upgrade.sources.clone()),
            };
            reporter.issue(
                context,
                Fault::connection(
                    self.directions.flow(Side::Client),
                    Status::Malformed,
                    issue.code,
                    issue.detail,
                )
                .with_evidence(wire, sources),
            )?;
        }
        if let Some(mut msg) = offer.msg.take() {
            context.release_all(&mut msg.charge)?;
        }
        Ok(())
    }

    fn sync_upgrade_server_decoder(
        &mut self,
        pending: &super::super::settings::PendingSettings,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let Some(server) = self.directions.server.as_mut() else {
            return Ok(());
        };
        if let Some(decoder) = server.decoder.as_mut() {
            if let Some(min) = pending.minimum_table_size {
                decoder.acknowledge_table_size(min)?;
            }
            decoder.acknowledge_table_size(pending.final_values.header_table_size)?;
        }
        server.sync_decoder(context)
    }

    fn open_upgraded_stream_one(
        &mut self,
        index: u64,
        method: Option<String>,
        mut offer: Offer,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        reporter.startup = Startup::H2c;
        self.upgrade.refused = false;
        self.streams.set_max_initiated(Side::Client, 1);
        let windows = self.control.initial_windows();
        let mut stream = StreamState::open(Side::Client, windows);
        stream.request = Some(index);
        stream.method = method.map(Bytes::from);
        let request_done = offer.msg.is_some()
            || self
                .prelude
                .as_ref()
                .is_none_or(|prelude| prelude.sides[Side::Client].live_message.is_none());
        stream.ended[Side::Client] = request_done;
        self.streams.admit_open(1, stream, false, context)?;
        if let Some(server) = self.directions.server.as_mut() {
            server.phase = DirectionPhase::Frames;
        }
        if request_done {
            if let Some(mut msg) = offer.msg.take() {
                msg.stream_id = 1;
                self.emit_message(Side::Client, msg, Status::Complete, reporter, context)?;
            }
            self.directions.client.phase = DirectionPhase::Preface;
            self.release_prelude(context)?;
        } else if let Some(prelude) = self.prelude.as_mut() {
            prelude.insert_offer(
                index,
                Offer {
                    settings: Vec::new(),
                    msg: offer.msg.take(),
                },
                context,
            )?;
        }
        Ok(())
    }

    pub(crate) fn release_prelude(&mut self, context: &mut Context<'_>) -> Result<(), Error> {
        let Some(prelude) = self.prelude.take() else {
            return Ok(());
        };
        prelude.release_all(context)
    }
}
