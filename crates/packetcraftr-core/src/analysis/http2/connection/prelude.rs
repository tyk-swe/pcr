// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::Error;
use super::super::buffer::union_balanced;
use super::super::model::{Certainty, Header, IssueScope, MessageKind, Startup, Status};
use super::super::stream::{CLIENT, MsgBuild, SERVER, StreamState};
use super::super::upgrade::{self, Offer, Pending};
use super::{Conn, Cx, DirPhase, Fault, Phase, resources};
use crate::analysis::application;
use crate::protocol::application::http::{self, BodyDecoder, StartLine};
use bytes::Bytes;

enum BodyStep {
    NotBody,
    Progress,
    Stalled,
    Complete(Box<MsgBuild>),
}

impl Conn {
    pub(crate) fn prelude_step(&mut self, side: usize, cx: &mut Cx<'_>) -> Result<bool, Error> {
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
        cx.charge_live(scratch)?;
        let result = self.prelude_step_inner(side, cx);
        cx.release_live(scratch);
        result
    }

    fn prelude_step_inner(&mut self, side: usize, cx: &mut Cx<'_>) -> Result<bool, Error> {
        match self.prelude_body_step(side, cx)? {
            BodyStep::NotBody => {}
            BodyStep::Progress => return Ok(true),
            BodyStep::Stalled => return Ok(false),
            BodyStep::Complete(msg) => return self.body_complete(side, *msg, cx),
        }
        if side == CLIENT {
            self.client_prelude_step(cx)
        } else {
            self.server_prelude_step(cx)
        }
    }

    fn drop_msg(&mut self, msg: MsgBuild, cx: &mut Cx<'_>) {
        self.release_conn(cx, msg.charged);
        *cx.spans = cx.spans.checked_sub(msg.charged_spans).expect("msg spans");
    }

    fn refused_upgrade(&mut self, mut msg: MsgBuild, cx: &mut Cx<'_>) -> Result<(), Error> {
        let head = msg.upgrade_head.take().expect("upgrade request head");
        let sources = union_balanced(std::mem::take(&mut msg.sets))?;
        self.drop_msg(msg, cx);
        self.issue(
            cx,
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

    fn prelude_body_step(&mut self, side: usize, cx: &mut Cx<'_>) -> Result<BodyStep, Error> {
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
                Self::release_dir(dir, cx, take);
                Self::release_dropped(dir, dropped, cx);
                let status = if matches!(error, http::Error::Limit(_)) {
                    Status::Limit
                } else {
                    Status::Malformed
                };
                self.issue(
                    cx,
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
                self.fail(cx, status)?;
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
            Self::release_dir(dir, cx, consumed);
            Self::release_dropped(dir, dropped, cx);
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
                    self.charge_conn(cx, charge)?;
                    cx.charge_spans(frames)?;
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
                        self.charge_conn(cx, trailer_charge)?;
                        msg.charged += trailer_charge;
                        msg.trailers = trailers;
                    }
                    BodyStep::Complete(Box::new(msg))
                }
                None => BodyStep::Progress,
            };
            let charge =
                std::mem::take(&mut self.prelude.as_mut().expect("prelude").body_charge[side]);
            self.release_conn(cx, charge);
            return Ok(step);
        }
        Ok(BodyStep::Progress)
    }

    fn body_complete(
        &mut self,
        side: usize,
        msg: MsgBuild,
        cx: &mut Cx<'_>,
    ) -> Result<bool, Error> {
        if side == SERVER {
            self.drop_msg(msg, cx);
            return Ok(true);
        }
        let Some(prelude) = self.prelude.as_mut() else {
            self.drop_msg(msg, cx);
            return Ok(true);
        };
        let index = msg.index;
        if let Some(offer) = prelude.offers.get_mut(&index) {
            offer.msg = Some(msg);
            if prelude.upgraded {
                let offer = prelude.offers.remove(&index).expect("offer");
                self.complete_upgrade_request(offer, cx)?;
            }
        } else {
            self.drop_msg(msg, cx);
        }
        Ok(true)
    }

    fn complete_upgrade_request(&mut self, offer: Offer, cx: &mut Cx<'_>) -> Result<(), Error> {
        self.release_conn(
            cx,
            resources::OFFER_OVERHEAD + offer.settings.capacity() * 24,
        );
        if let Some(mut msg) = offer.msg {
            msg.stream_id = 1;
            self.emit_message(CLIENT, msg, Status::Complete, cx)?;
        }
        self.end_side(CLIENT, 1, Status::Complete, cx)?;
        if let Some(dir) = self.dirs[CLIENT].as_mut() {
            dir.phase = DirPhase::Preface;
        }
        self.phase = Phase::H2;
        self.release_prelude(cx)?;
        Ok(())
    }

    fn client_prelude_step(&mut self, cx: &mut Cx<'_>) -> Result<bool, Error> {
        let dir =
            self.dirs[CLIENT]
                .as_mut()
                .ok_or(Error::Application(application::Error::Sources {
                    number: self.number,
                }))?;
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
                Self::release_dir(dir, cx, take);
                Self::release_dropped(dir, dropped, cx);
                self.issue(
                    cx,
                    Fault {
                        flow,
                        http2_stream_id: None,
                        scope: IssueScope::Connection,
                        certainty: Certainty::Confirmed,
                        status: Status::Malformed,
                        code: "prelude_head",
                        detail: error.to_string().into(),
                        wire,
                        sources,
                    },
                )?;
                self.fail(cx, Status::Malformed)?;
                return Ok(true);
            }
        };
        if !matches!(head.start, StartLine::Request { .. }) {
            let flow = dir.flow.clone();
            let sets = dir.buffer.contributors(consumed.min(dir.buffer.len()));
            let (_, dropped) = dir.buffer.take(consumed.min(dir.buffer.len()));
            let sources = union_balanced(sets)?;
            Self::release_dir(dir, cx, consumed);
            Self::release_dropped(dir, dropped, cx);
            self.issue(
                cx,
                Fault {
                    flow,
                    http2_stream_id: None,
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "prelude_not_request",
                    detail: "the client direction did not carry a request head".into(),
                    wire: Bytes::copy_from_slice(&view[..consumed.min(256)]),
                    sources,
                },
            )?;
            self.fail(cx, Status::Malformed)?;
            return Ok(true);
        }
        let sets = dir.buffer.contributors(consumed);
        let (head_wire_bytes, dropped) = dir.buffer.take(consumed);
        Self::release_dir(dir, cx, consumed);
        Self::release_dropped(dir, dropped, cx);
        let (head, _) =
            http::parse_head(&head_wire_bytes)?.expect("previously parsed complete HTTP/1 head");
        let head_wire = head_wire_bytes.len();
        let method = head.method().map(str::to_owned);
        let offer = match upgrade::upgrade_offer(&head) {
            Ok(offer) => offer,
            Err(detail) => {
                self.issue(
                    cx,
                    Fault {
                        flow: self.dir_flow(CLIENT),
                        http2_stream_id: None,
                        scope: IssueScope::Connection,
                        certainty: Certainty::Confirmed,
                        status: Status::Unsupported,
                        code: "bad_upgrade_offer",
                        detail: detail.into(),
                        wire: head_wire_bytes,
                        sources: union_balanced(sets.clone())?,
                    },
                )?;
                None
            }
        };
        let mut msg = self.new_message(0, MessageKind::Request, cx)?;
        self.charge_conn(cx, head_wire)?;
        msg.charged += head_wire;
        msg.upgrade_head = Some(head.clone());
        let header_charge = head
            .headers
            .iter()
            .map(|h| h.name.len() + h.value.len() + resources::HEADER_OVERHEAD)
            .sum::<usize>();
        self.charge_conn(cx, header_charge)?;
        msg.charged += header_charge;
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
            let frames = set.frames().len();
            let charge = resources::SET_OVERHEAD + frames * resources::SPAN_OVERHEAD;
            self.charge_conn(cx, charge)?;
            cx.charge_spans(frames)?;
            msg.charged += charge;
            msg.charged_spans += frames;
            msg.sets.push(set);
        }
        let index = msg.index;
        if self.prelude.as_ref().expect("prelude").requests.len() >= cx.limits.max_active_streams {
            let sources = union_balanced(std::mem::take(&mut msg.sets))?;
            self.drop_msg(msg, cx);
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(CLIENT),
                    http2_stream_id: None,
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Limit,
                    code: "pending_requests",
                    detail: "pre-upgrade requests exceed the configured bound".into(),
                    wire: head.wire().clone(),
                    sources,
                },
            )?;
            self.fail(cx, Status::Limit)?;
            return Ok(true);
        }
        self.charge_conn(cx, resources::PENDING_OVERHEAD)?;
        let prelude = self.prelude.as_mut().expect("prelude");
        prelude.requests.push_back(Pending {
            index,
            method: method.clone(),
            upgrade: offer.is_some(),
        });
        if let Some(settings) = offer {
            let charge = resources::OFFER_OVERHEAD + settings.capacity() * 24;
            self.charge_conn(cx, charge)?;
            let prelude = self.prelude.as_mut().expect("prelude");
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
                self.drop_msg(msg, cx);
                self.issue(
                    cx,
                    Fault {
                        flow: self.dir_flow(CLIENT),
                        http2_stream_id: None,
                        scope: IssueScope::Connection,
                        certainty: Certainty::Confirmed,
                        status: Status::Malformed,
                        code: "prelude_framing",
                        detail: error.to_string().into(),
                        wire: head.wire().clone(),
                        sources,
                    },
                )?;
                self.fail(cx, Status::Malformed)?;
                return Ok(true);
            }
        };
        let is_offer = self
            .prelude
            .as_ref()
            .is_some_and(|p| p.offers.contains_key(&index));
        if matches!(framing, http::Body::Chunked) {
            if let Err(error) = self.charge_conn(cx, resources::PRELUDE_BODY_RESERVE) {
                self.drop_msg(msg, cx);
                return Err(error);
            }
            self.prelude.as_mut().expect("prelude").body_charge[CLIENT] =
                resources::PRELUDE_BODY_RESERVE;
        }
        let decoder = BodyDecoder::new(framing, cx.limits.max_body_bytes);
        if decoder.complete() {
            if is_offer {
                let prelude = self.prelude.as_mut().expect("prelude");
                if let Some(offer) = prelude.offers.get_mut(&index) {
                    offer.msg = Some(msg);
                }
                if prelude.upgraded {
                    let offer = prelude.offers.remove(&index).expect("offer");
                    self.complete_upgrade_request(offer, cx)?;
                }
            } else {
                self.drop_msg(msg, cx);
            }
        } else {
            let prelude = self.prelude.as_mut().expect("prelude");
            prelude.client_body = Some(decoder);
            prelude.live_request = Some(msg);
        }
        Ok(true)
    }

    fn server_prelude_step(&mut self, cx: &mut Cx<'_>) -> Result<bool, Error> {
        let dir =
            self.dirs[SERVER]
                .as_mut()
                .ok_or(Error::Application(application::Error::Sources {
                    number: self.number,
                }))?;
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
                Self::release_dir(dir, cx, take);
                Self::release_dropped(dir, dropped, cx);
                self.issue(
                    cx,
                    Fault {
                        flow,
                        http2_stream_id: None,
                        scope: IssueScope::Connection,
                        certainty: Certainty::Confirmed,
                        status: Status::Malformed,
                        code: "prelude_head",
                        detail: error.to_string().into(),
                        wire,
                        sources,
                    },
                )?;
                self.fail(cx, Status::Malformed)?;
                return Ok(true);
            }
        };
        if !matches!(head.start, StartLine::Response { .. }) {
            let flow = dir.flow.clone();
            let release_len = consumed.min(dir.buffer.len());
            let sets = dir.buffer.contributors(release_len);
            let (_, dropped) = dir.buffer.take(release_len);
            let sources = union_balanced(sets)?;
            Self::release_dir(dir, cx, release_len);
            Self::release_dropped(dir, dropped, cx);
            self.issue(
                cx,
                Fault {
                    flow,
                    http2_stream_id: None,
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "prelude_not_response",
                    detail: "the server direction did not carry a response head".into(),
                    wire: Bytes::copy_from_slice(&view[..consumed.min(256)]),
                    sources,
                },
            )?;
            self.fail(cx, Status::Malformed)?;
            return Ok(true);
        }
        let sets = dir.buffer.contributors(consumed);
        let (head_wire_bytes, dropped) = dir.buffer.take(consumed);
        Self::release_dir(dir, cx, consumed);
        Self::release_dropped(dir, dropped, cx);
        let (head, _) =
            http::parse_head(&head_wire_bytes)?.expect("previously parsed complete HTTP/1 head");
        let head_wire = head_wire_bytes.len();
        let status = head.status().expect("response");
        let front = self.prelude.as_mut().and_then(|p| {
            p.requests
                .front()
                .map(|p| (p.index, p.method.clone(), p.upgrade))
        });
        let matched = front.as_ref().is_some_and(|(index, _, upgrade)| {
            *upgrade
                && self
                    .prelude
                    .as_ref()
                    .is_some_and(|p| p.offers.contains_key(index))
        });
        if status == 101 {
            if matched && upgrade::accepts_upgrade(&head) {
                let (index, method, _) = front.clone().expect("front");
                let prelude = self.prelude.as_mut().expect("prelude");
                prelude.requests.pop_front();
                self.release_conn(cx, resources::PENDING_OVERHEAD);
                self.accept_upgrade(index, head, head_wire_bytes, sets, method, cx)?;
                return Ok(true);
            }
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(SERVER),
                    http2_stream_id: None,
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Unsupported,
                    code: "unexpected_101",
                    detail: "a 101 response does not match a pending h2c offer".into(),
                    wire: head_wire_bytes,
                    sources: union_balanced(sets)?,
                },
            )?;
            self.fail(cx, Status::Unsupported)?;
            return Ok(true);
        }
        let mut msg = self.new_message(0, MessageKind::Response, cx)?;
        self.charge_conn(cx, head_wire)?;
        msg.charged += head_wire;
        let header_charge = head
            .headers
            .iter()
            .map(|h| h.name.len() + h.value.len() + resources::HEADER_OVERHEAD)
            .sum::<usize>();
        self.charge_conn(cx, header_charge)?;
        msg.charged += header_charge;
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
            let frames = set.frames().len();
            let charge = resources::SET_OVERHEAD + frames * resources::SPAN_OVERHEAD;
            self.charge_conn(cx, charge)?;
            cx.charge_spans(frames)?;
            msg.charged += charge;
            msg.charged_spans += frames;
            msg.sets.push(set);
        }
        if let Some((index, ..)) = front {
            msg.request = Some(index);
        }
        let informational = status < 200;
        if informational {
            self.drop_msg(msg, cx);
            return Ok(true);
        }
        let had_front = front.is_some();
        let (front_index, method, was_upgrade) = front.unwrap_or((0, None, false));
        if had_front {
            let prelude = self.prelude.as_mut().expect("prelude");
            prelude.requests.pop_front();
            self.release_conn(cx, resources::PENDING_OVERHEAD);
        }
        if was_upgrade {
            if let Some(mut offer) = self
                .prelude
                .as_mut()
                .and_then(|prelude| prelude.offers.remove(&front_index))
            {
                self.release_conn(
                    cx,
                    resources::OFFER_OVERHEAD + offer.settings.capacity() * 24,
                );
                if let Some(held) = offer.msg.take() {
                    self.refused_upgrade(held, cx)?;
                }
            }
            let live = self.prelude.as_mut().and_then(|prelude| {
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
                self.refused_upgrade(live, cx)?;
            }
            self.refused = true;
        }
        let framing = match head.body(method.as_deref()) {
            Ok(framing) => framing,
            Err(error) => {
                let sources = union_balanced(std::mem::take(&mut msg.sets))?;
                self.drop_msg(msg, cx);
                self.issue(
                    cx,
                    Fault {
                        flow: self.dir_flow(SERVER),
                        http2_stream_id: None,
                        scope: IssueScope::Connection,
                        certainty: Certainty::Confirmed,
                        status: Status::Malformed,
                        code: "prelude_framing",
                        detail: error.to_string().into(),
                        wire: head.wire().clone(),
                        sources,
                    },
                )?;
                self.fail(cx, Status::Malformed)?;
                return Ok(true);
            }
        };
        if matches!(framing, http::Body::Chunked) {
            if let Err(error) = self.charge_conn(cx, resources::PRELUDE_BODY_RESERVE) {
                self.drop_msg(msg, cx);
                return Err(error);
            }
            self.prelude.as_mut().expect("prelude").body_charge[SERVER] =
                resources::PRELUDE_BODY_RESERVE;
        }
        let decoder = BodyDecoder::new(framing, cx.limits.max_body_bytes);
        if decoder.complete() {
            self.drop_msg(msg, cx);
        } else {
            let prelude = self.prelude.as_mut().expect("prelude");
            prelude.server_body = Some(decoder);
            prelude.live_response = Some(msg);
        }
        Ok(true)
    }

    fn accept_upgrade(
        &mut self,
        index: u64,
        head: http::Head,
        head_wire: Bytes,
        sets: Vec<crate::analysis::provenance::SourceSet>,
        method: Option<String>,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        let sources = union_balanced(sets)?;
        let mut prelude = self.prelude.take().expect("prelude");
        let Some(mut offer) = prelude.offers.remove(&index) else {
            self.prelude = Some(prelude);
            return Ok(());
        };
        self.release_conn(
            cx,
            resources::OFFER_OVERHEAD + offer.settings.capacity() * 24,
        );
        prelude.upgraded = true;
        let upgrade_charge = head_wire.len()
            + resources::SET_OVERHEAD
            + sources.as_ref().map_or(0, |s| s.frames().len()) * resources::SPAN_OVERHEAD
            + offer.settings.len() * 8
            + resources::OFFER_OVERHEAD;
        self.charge_conn(cx, upgrade_charge)?;
        self.upgrade_charge += upgrade_charge;
        self.upgrade_response = Some(head);
        self.upgrade_sources = sources;
        let applied = {
            let direction = &mut self.settings[CLIENT];
            let applied = direction.apply(&offer.settings, false);
            direction.acknowledged = direction.advertised;
            applied
        };
        for issue in applied.issues {
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(CLIENT),
                    http2_stream_id: None,
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: issue.code,
                    detail: issue.detail.into(),
                    wire: head_wire.clone(),
                    sources: self.upgrade_sources.clone(),
                },
            )?;
        }
        if let Some(dir) = self.dirs[SERVER].as_mut()
            && let Some(decoder) = dir.decoder.as_mut()
        {
            if let Some(min) = applied.pending.minimum_table_size {
                decoder.acknowledge_table_size(min)?;
            }
            decoder.acknowledge_table_size(applied.pending.final_values.header_table_size)?;
        }
        self.decoder_sync(SERVER, cx)?;
        for delta in &applied.pending.window_deltas {
            for stream in self.streams.values_mut() {
                stream.send_window[SERVER] += *delta;
            }
        }
        self.startup = Startup::H2c;
        self.refused = false;
        self.max_initiated[CLIENT] = 1;
        self.charge_conn(cx, resources::STREAM_OVERHEAD)?;
        let windows = [
            i64::from(self.settings[SERVER].acknowledged.initial_window_size),
            i64::from(self.settings[CLIENT].acknowledged.initial_window_size),
        ];
        let mut stream = StreamState::open(true, windows);
        stream.request = Some(index);
        stream.method = method.map(Bytes::from);
        let request_done = offer.msg.is_some() || prelude.live_request.is_none();
        stream.ended[CLIENT] = request_done;
        cx.check_streams()?;
        self.admitted_streams += 1;
        self.streams.insert(1, stream);
        self.active[CLIENT] += 1;
        if let Some(dir) = self.dirs[SERVER].as_mut() {
            dir.phase = DirPhase::Frames;
        }
        if request_done {
            if let Some(mut msg) = offer.msg.take() {
                msg.stream_id = 1;
                self.emit_message(CLIENT, msg, Status::Complete, cx)?;
            }
            if let Some(dir) = self.dirs[CLIENT].as_mut() {
                dir.phase = DirPhase::Preface;
            }
            self.phase = Phase::H2;
            self.prelude = Some(prelude);
            self.release_prelude(cx)?;
        } else {
            self.charge_conn(cx, resources::OFFER_OVERHEAD)?;
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
