// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod body;
mod request;
mod response;

use body::BodyStep;

use super::super::Error;
use super::super::buffer::union_balanced;
use super::super::model::{Certainty, IssueScope, Startup, Status};
use super::super::stream::{CLIENT, MessageBuilder, SERVER, StreamState};
use super::super::upgrade::Offer;
use super::{ConnectionState, Context, DirectionPhase, Fault, Phase, resources};
use crate::protocol::application::http;
use bytes::Bytes;

impl ConnectionState {
    pub(crate) fn prelude_step(
        &mut self,
        side: usize,
        context: &mut Context<'_>,
    ) -> Result<bool, Error> {
        let body_active = self.prelude.as_ref().is_some_and(|prelude| {
            if side == CLIENT {
                prelude.client_body.is_some()
            } else {
                prelude.server_body.is_some()
            }
        });
        let buffered = self.dirs[side].as_ref().map_or(0, |dir| dir.buffer.len());
        let scratch = if body_active || buffered == 0 {
            0
        } else {
            buffered.min(http::MAX_HEADER_BYTES + 1) * 4 + resources::PRELUDE_HEADER_OVERHEAD
        };
        context.charge_live(scratch)?;
        let result = self.prelude_step_inner(side, context);
        context.release_live(scratch);
        result
    }

    fn prelude_step_inner(
        &mut self,
        side: usize,
        context: &mut Context<'_>,
    ) -> Result<bool, Error> {
        match self.prelude_body_step(side, context)? {
            BodyStep::NotBody => {}
            BodyStep::Progress => return Ok(true),
            BodyStep::Stalled => return Ok(false),
            BodyStep::Complete(msg) => return self.body_complete(side, *msg, context),
        }
        if side == CLIENT {
            self.client_prelude_step(context)
        } else {
            self.server_prelude_step(context)
        }
    }

    fn drop_msg(&mut self, msg: MessageBuilder, context: &mut Context<'_>) {
        self.release_conn(context, msg.charged);
        *context.spans = context
            .spans
            .checked_sub(msg.charged_spans)
            .expect("msg spans");
    }

    fn refused_upgrade(
        &mut self,
        mut msg: MessageBuilder,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let head = msg.upgrade_head.take().expect("upgrade request head");
        let sources = union_balanced(std::mem::take(&mut msg.sets))?;
        self.drop_msg(msg, context);
        self.issue(
            context,
            Fault {
                flow: self.dir_flow(CLIENT),
                http2_stream_id: None,
                scope: IssueScope::Connection,
                certainty: Certainty::Confirmed,
                // A refusal is a complete HTTP/1 exchange, not an HTTP/2 error.
                // EOF classifies the connection as unsupported if no retry succeeds.
                status: Status::Complete,
                code: "refused_upgrade",
                detail: "the server declined this h2c upgrade request".into(),
                wire: head.wire().clone(),
                sources,
            },
        )
    }

    fn body_complete(
        &mut self,
        side: usize,
        msg: MessageBuilder,
        context: &mut Context<'_>,
    ) -> Result<bool, Error> {
        if side == SERVER {
            self.drop_msg(msg, context);
            return Ok(true);
        }
        let Some(prelude) = self.prelude.as_mut() else {
            self.drop_msg(msg, context);
            return Ok(true);
        };
        let index = msg.index;
        if let Some(offer) = prelude.offers.get_mut(&index) {
            offer.msg = Some(msg);
            if prelude.upgraded {
                let offer = prelude.offers.remove(&index).expect("offer");
                self.complete_upgrade_request(offer, context)?;
            }
        } else {
            self.drop_msg(msg, context);
        }
        Ok(true)
    }

    fn complete_upgrade_request(
        &mut self,
        offer: Offer,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        self.release_conn(
            context,
            resources::OFFER_OVERHEAD + offer.settings.capacity() * 24,
        );
        if let Some(mut msg) = offer.msg {
            msg.stream_id = 1;
            self.emit_message(CLIENT, msg, Status::Complete, context)?;
        }
        self.end_side(CLIENT, 1, Status::Complete, context)?;
        if let Some(dir) = self.dirs[CLIENT].as_mut() {
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
        let mut prelude = self.prelude.take().expect("prelude");
        let Some(mut offer) = prelude.offers.remove(&index) else {
            self.prelude = Some(prelude);
            return Ok(());
        };
        self.release_conn(
            context,
            resources::OFFER_OVERHEAD + offer.settings.capacity() * 24,
        );
        prelude.upgraded = true;
        let upgrade_charge = head_wire.len()
            + resources::SET_OVERHEAD
            + sources.as_ref().map_or(0, |s| s.frames().len()) * resources::SPAN_OVERHEAD
            + offer.settings.len() * 8
            + resources::OFFER_OVERHEAD;
        self.charge_conn(context, upgrade_charge)?;
        self.upgrade_charge += upgrade_charge;
        self.upgrade_response = Some(head);
        self.upgrade_sources = sources;
        let applied = {
            let direction = &mut self.settings[CLIENT];
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
                        .expect("upgrade request head")
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
                Fault {
                    flow: self.dir_flow(CLIENT),
                    http2_stream_id: None,
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: issue.code,
                    detail: issue.detail.into(),
                    wire: request_evidence
                        .as_ref()
                        .map_or_else(|| head_wire.clone(), |(wire, _)| wire.clone()),
                    sources: request_evidence.as_ref().map_or_else(
                        || self.upgrade_sources.clone(),
                        |(_, sources)| sources.clone(),
                    ),
                },
            )?;
        }
        if invalid {
            if let Some(msg) = offer.msg.take() {
                self.drop_msg(msg, context);
            }
            self.prelude = Some(prelude);
            self.fail(context, Status::Malformed)?;
            return Ok(());
        }
        if let Some(dir) = self.dirs[SERVER].as_mut()
            && let Some(decoder) = dir.decoder.as_mut()
        {
            if let Some(min) = applied.pending.minimum_table_size {
                decoder.acknowledge_table_size(min)?;
            }
            decoder.acknowledge_table_size(applied.pending.final_values.header_table_size)?;
        }
        self.decoder_sync(SERVER, context)?;
        for stream in self.streams.values_mut() {
            context.check_deadline()?;
            stream.send_window[SERVER] += applied.pending.window_delta;
        }
        self.startup = Startup::H2c;
        self.refused = false;
        self.max_initiated[CLIENT] = 1;
        self.charge_conn(context, resources::STREAM_OVERHEAD)?;
        let windows = [
            i64::from(self.settings[SERVER].acknowledged.initial_window_size),
            i64::from(self.settings[CLIENT].acknowledged.initial_window_size),
        ];
        let mut stream = StreamState::open(true, windows);
        stream.request = Some(index);
        stream.method = method.map(Bytes::from);
        let request_done = offer.msg.is_some() || prelude.live_request.is_none();
        stream.ended[CLIENT] = request_done;
        context.check_streams()?;
        self.admitted_streams += 1;
        self.streams.insert(1, stream);
        self.active[CLIENT] += 1;
        if let Some(dir) = self.dirs[SERVER].as_mut() {
            dir.phase = DirectionPhase::Frames;
        }
        if request_done {
            if let Some(mut msg) = offer.msg.take() {
                msg.stream_id = 1;
                self.emit_message(CLIENT, msg, Status::Complete, context)?;
            }
            if let Some(dir) = self.dirs[CLIENT].as_mut() {
                dir.phase = DirectionPhase::Preface;
            }
            self.phase = Phase::H2;
            self.prelude = Some(prelude);
            self.release_prelude(context)?;
        } else {
            self.charge_conn(context, resources::OFFER_OVERHEAD)?;
            prelude.offers.insert(
                index,
                Offer {
                    settings: Vec::new(),
                    msg: offer.msg.take(),
                },
            );
            self.prelude = Some(prelude);
        }
        Ok(())
    }
}
