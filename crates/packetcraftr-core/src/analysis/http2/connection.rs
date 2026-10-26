// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Connection and direction state, input buffering, and processing pumps.

pub(crate) mod control;
pub(crate) mod frames;
pub(crate) mod lifecycle;
pub(crate) mod prelude;
pub(crate) mod startup;
pub(crate) mod streams;

pub(crate) use super::budget::Context;

use super::budget::{self, Charge};
use crate::analysis::http2::IssueCode;

use super::Error;
use super::buffer::SourceBuffer;
use super::model::{Certainty, Issue, IssueScope, Startup, Status};
use super::settings::DirectionSettings;
use super::stream::{MessageBuilder, StreamState};
use super::upgrade::Prelude;
use crate::analysis::application::{self, Delivery};
use crate::analysis::http2::side::{PerSide, Side};
use crate::analysis::provenance::SourceSet;
use crate::analysis::reassembly::tcp::ScopedFlowKey;
use crate::protocol::application::http2 as wire;
use crate::protocol::application::http2::hpack;
use bytes::Bytes;
use std::collections::{BTreeMap, HashMap, VecDeque};

pub(crate) const PREFACE_LEN: usize = 24;
const READ_CHUNK: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Sniff,
    Prelude,
    H2,
    Dead,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectionPhase {
    Sniff,
    Prelude,
    Preface,
    Frames,
}

pub(crate) struct Chain {
    pub stream_id: u32,
    pub head: ChainHead,
    pub bytes: bytes::BytesMut,
    pub frames: usize,
    pub sets: Vec<SourceSet>,
    pub charge: Charge,
}
#[derive(Clone, Copy)]
pub(crate) enum ChainHead {
    Headers { end_stream: bool, malformed: bool },
    PushPromise { promised: u32 },
}

pub(crate) struct DirectionState {
    pub flow: ScopedFlowKey,
    pub phase: DirectionPhase,
    pub buffer: SourceBuffer,
    pub decoder: Option<hpack::Decoder>,
    pub decoder_charge: Charge,
    pub block_sources: HashMap<u64, SourceSet>,
    pub chain: Option<Chain>,
    pub closed: bool,
    pub fully_consumed_fin: bool,
    pub saw_frame: bool,
    pub received: bool,
    pub garbage: bool,
    pub charge: Charge,
}
impl DirectionState {
    pub(crate) fn new(flow: ScopedFlowKey) -> Self {
        Self {
            flow,
            phase: DirectionPhase::Sniff,
            buffer: SourceBuffer::new(),
            decoder: None,
            decoder_charge: Charge::default(),
            block_sources: HashMap::new(),
            chain: None,
            closed: false,
            fully_consumed_fin: false,
            saw_frame: false,
            received: false,
            garbage: false,
            charge: Charge::default(),
        }
    }

    pub(crate) fn release_consumed(
        &mut self,
        bytes: usize,
        dropped: Vec<SourceSet>,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        context.release(&mut self.charge, bytes)?;
        dropped
            .iter()
            .try_for_each(|set| context.untrack(&mut self.charge, set))
    }

    pub(crate) fn release_all(&mut self, context: &mut Context<'_>) -> Result<(), Error> {
        context.release_all(&mut self.charge)?;
        context.release_all(&mut self.decoder_charge)?;
        self.chain
            .as_mut()
            .map_or(Ok(()), |chain| context.release_all(&mut chain.charge))
    }
}

pub(crate) struct Fault {
    pub flow: ScopedFlowKey,
    pub http2_stream_id: Option<u32>,
    pub scope: IssueScope,
    pub certainty: Certainty,
    pub status: Status,
    pub code: IssueCode,
    pub detail: std::borrow::Cow<'static, str>,
    pub wire: Bytes,
    pub sources: Option<SourceSet>,
}

pub(crate) struct Decoded {
    pub headers: Vec<super::model::Header>,
    pub block: Bytes,
    pub sources: Option<SourceSet>,
    pub compression: Option<SourceSet>,
}

pub(crate) struct Head {
    pub role: super::headers::FieldRole,
    pub meta: super::headers::Meta,
    pub flawed: bool,
}

pub(crate) struct Pos {
    pub side: Side,
    pub stream_id: u32,
}

#[derive(Clone)]
pub(crate) struct Evidence {
    pub wire: Bytes,
    pub sources: Option<SourceSet>,
}

pub(crate) struct ClosedStream {
    pub ended: PerSide<bool>,
    pub reset_by: Option<Side>,
    pub request: Option<u64>,
}

pub(crate) struct ConnectionState {
    pub stream: u64,
    pub generation: u64,
    pub first_flow: ScopedFlowKey,
    pub startup: Startup,
    pub status: Status,
    pub phase: Phase,
    pub pending: Vec<DirectionState>,
    pub dirs: PerSide<Option<DirectionState>>,
    pub prelude: Option<Prelude>,
    pub streams: BTreeMap<u32, StreamState>,
    pub closed: BTreeMap<u32, ClosedStream>,
    pub early_response_headers: BTreeMap<u32, super::stream::EarlyResponse>,
    pub closed_credit: BTreeMap<u32, PerSide<Option<i64>>>,
    pub admitted_streams: u64,
    pub max_initiated: PerSide<u32>,
    pub active: PerSide<usize>,
    pub send_window: PerSide<i64>,
    pub settings: PerSide<DirectionSettings>,
    pub goaway: PerSide<Option<u32>>,
    pub next_origin: u64,
    pub frames: u64,
    pub issues: u64,
    pub emitted: bool,
    pub clean_start: bool,
    pub number: u64,
    pub charge: Charge,
    pub upgrade_response: Option<crate::protocol::application::http::Head>,
    pub upgrade_sources: Option<SourceSet>,
    pub upgrade_charge: Charge,
    pub final_pending_settings: Option<u64>,
    pub pings: PerSide<BTreeMap<[u8; 8], u64>>,
    pub final_pending_pings: Option<u64>,
    pub refused: bool,
    pub done: bool,
    pub finalizing: bool,
    pub resume_side: Option<Side>,
    pub pending_openers: BTreeMap<u32, IssueCode>,
    pub parent_deferred: VecDeque<MessageBuilder>,
    pub ack_deferred: VecDeque<(Side, MessageBuilder, Status)>,
}

impl ConnectionState {
    pub(crate) fn new(stream: u64, generation: u64, flow: ScopedFlowKey) -> Self {
        Self {
            stream,
            generation,
            first_flow: flow,
            startup: Startup::Unknown,
            status: Status::Complete,
            phase: Phase::Sniff,
            pending: Vec::new(),
            dirs: PerSide::new(None, None),
            prelude: None,
            streams: BTreeMap::new(),
            closed: BTreeMap::new(),
            early_response_headers: BTreeMap::new(),
            closed_credit: BTreeMap::new(),
            admitted_streams: 0,
            max_initiated: PerSide::new(0, 0),
            active: PerSide::new(0, 0),
            send_window: PerSide::new(65_535, 65_535),
            settings: PerSide::new(DirectionSettings::new(), DirectionSettings::new()),
            goaway: PerSide::new(None, None),
            next_origin: 1,
            frames: 0,
            issues: 0,
            emitted: false,
            clean_start: true,
            number: 0,
            charge: Charge::default(),
            upgrade_response: None,
            upgrade_sources: None,
            upgrade_charge: Charge::default(),
            final_pending_settings: None,
            pings: PerSide::new(BTreeMap::new(), BTreeMap::new()),
            final_pending_pings: None,
            refused: false,
            done: false,
            finalizing: false,
            resume_side: None,
            pending_openers: BTreeMap::new(),
            parent_deferred: VecDeque::new(),
            ack_deferred: VecDeque::new(),
        }
    }

    pub(crate) fn flow(&self) -> ScopedFlowKey {
        self.dirs[Side::Client]
            .as_ref()
            .or(self.dirs[Side::Server].as_ref())
            .or_else(|| self.pending.first())
            .map(|dir| dir.flow.clone())
            .unwrap_or_else(|| self.first_flow.clone())
    }

    fn issue_frame_number(&self, sources: &Option<SourceSet>) -> Option<u64> {
        sources
            .as_ref()
            .and_then(|set| set.frames().last().map(|frame| frame.number))
    }

    pub(crate) fn dir_flow(&self, side: Side) -> ScopedFlowKey {
        self.dirs[side]
            .as_ref()
            .map(|dir| dir.flow.clone())
            .unwrap_or_else(|| self.flow())
    }

    pub(crate) fn dir_mut(&mut self, flow: &ScopedFlowKey) -> Option<&mut DirectionState> {
        self.dirs
            .iter_mut()
            .flatten()
            .find(|dir| dir.flow == *flow)
            .or_else(|| self.pending.iter_mut().find(|dir| dir.flow == *flow))
    }

    pub(crate) fn side_of(&self, flow: &ScopedFlowKey) -> Option<Side> {
        Side::BOTH.into_iter().find(|side| {
            self.dirs[*side]
                .as_ref()
                .is_some_and(|dir| dir.flow == *flow)
        })
    }

    pub(crate) fn has_flow(&self, flow: &ScopedFlowKey) -> bool {
        self.side_of(flow).is_some() || self.pending.iter().any(|dir| dir.flow == *flow)
    }

    pub(crate) fn issue(&mut self, context: &mut Context<'_>, fault: Fault) -> Result<(), Error> {
        let charge =
            fault.wire.len() + fault.detail.len() + budget::ISSUE_OVERHEAD + budget::EVENT_OVERHEAD;
        context.charge_retained(charge)?;
        if let Some(sources) = &fault.sources {
            context.charge_retained(
                budget::SET_OVERHEAD + sources.frames().len() * budget::SPAN_OVERHEAD,
            )?;
        }
        self.issues += 1;
        let number = self
            .issue_frame_number(&fault.sources)
            .unwrap_or(self.number);
        context.issue(Issue {
            number,
            stream: self.stream,
            generation: self.generation,
            http2_stream_id: fault.http2_stream_id,
            flow: fault.flow,
            code: fault.code,
            scope: fault.scope,
            certainty: fault.certainty,
            status: fault.status,
            detail: fault.detail.into_owned(),
            wire: fault.wire,
            sources: fault.sources,
        });
        if fault.certainty == Certainty::Confirmed || fault.scope == IssueScope::Capture {
            self.worst(fault.status);
        } else {
            self.worst(Status::Incomplete);
        }
        Ok(())
    }

    pub(crate) fn worst(&mut self, status: Status) {
        fn rank(s: Status) -> u8 {
            match s {
                Status::Complete => 0,
                Status::Incomplete | Status::Unprocessed => 1,
                Status::Unsupported => 2,
                Status::Gap | Status::Conflict | Status::Evicted | Status::Reset => 3,
                Status::Limit | Status::Malformed => 4,
            }
        }
        if rank(status) > rank(self.status) {
            self.status = status;
        }
    }

    pub(crate) fn data(
        &mut self,
        delivery: &Delivery,
        number: u64,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        self.number = number;
        if matches!(self.phase, Phase::Dead) {
            return Ok(());
        }
        if self.dir_mut(&delivery.flow).is_none() {
            let elected = self.dirs[Side::Client].is_some();
            if elected && self.dirs[Side::Server].is_none() {
                let mut dir = DirectionState::new(delivery.flow.clone());
                let mut decoder = hpack::Decoder::new(context.limits.hpack())?;
                decoder.permit_table_size(self.settings[Side::Client].advertised.header_table_size);
                for pending in &self.settings[Side::Client].pending {
                    decoder.permit_table_size(pending.final_values.header_table_size);
                }
                dir.decoder = Some(decoder);
                dir.phase = match self.phase {
                    Phase::H2 => DirectionPhase::Frames,
                    Phase::Prelude => DirectionPhase::Prelude,
                    _ => DirectionPhase::Sniff,
                };
                context.charge(&mut self.charge, budget::DIR_OVERHEAD)?;
                self.dirs[Side::Server] = Some(dir);
            } else if !elected && self.pending.len() < 2 {
                context.charge(&mut self.charge, budget::DIR_OVERHEAD)?;
                self.pending
                    .push(DirectionState::new(delivery.flow.clone()));
            }
        }
        if !delivery.bytes.is_empty()
            && let Some(dir) = self.dir_mut(&delivery.flow)
        {
            dir.received = true;
        }
        let mut cursor = 0usize;
        while cursor < delivery.bytes.len() {
            let Some(want) = self.next_want(&delivery.flow) else {
                break;
            };
            let remaining = delivery.bytes.len() - cursor;
            let want = want.min(remaining);
            if want == 0 {
                let before = self.buffered_len();
                self.pump(context)?;
                if self.buffered_len() == before {
                    return Err(Error::Application(application::Error::Limit {
                        field: "stalled_input",
                        limit: delivery.bytes.len(),
                    }));
                }
                if matches!(self.phase, Phase::Dead) {
                    return self.drain(context);
                }
                continue;
            }
            let chunk = delivery.bytes.slice(cursor..cursor + want);
            let dir = self
                .dir_mut(&delivery.flow)
                .ok_or(Error::Invariant("dir"))?;
            context.charge(&mut dir.charge, chunk.len())?;
            context.track(&mut dir.charge, &delivery.sources)?;
            dir.buffer.push(chunk, delivery.sources.clone());
            cursor += want;
            self.pump(context)?;
            if matches!(self.phase, Phase::Dead) {
                return self.drain(context);
            }
        }
        Ok(())
    }

    fn buffered_len(&self) -> usize {
        self.dirs
            .iter()
            .flatten()
            .chain(self.pending.iter())
            .map(|dir| dir.buffer.len())
            .sum()
    }

    pub(crate) fn waiting_settings_ack(&self, side: Side) -> bool {
        let peer = side.peer();
        if self.finalizing
            || !self.settings[peer].pending.is_empty()
            || self.dirs[peer].as_ref().is_some_and(|dir| dir.closed)
        {
            return false;
        }
        self.dirs[side].as_ref().is_some_and(|dir| {
            let bytes = dir.buffer.bytes();
            dir.saw_frame
                && dir.chain.is_none()
                && bytes.len() >= wire::HEADER_LEN
                && wire::declared_length(bytes) == 0
                && bytes[3] == wire::TYPE_SETTINGS
                && bytes[4] & wire::FLAG_ACK != 0
                && bytes[5] & 0x7f == 0
                && bytes[6..9] == [0, 0, 0]
        })
    }

    fn next_want(&self, flow: &ScopedFlowKey) -> Option<usize> {
        if self
            .side_of(flow)
            .is_some_and(|side| self.waiting_settings_ack(side))
        {
            // The already charged directional buffer bounds deferred ACKs and
            // following bytes while the opposite reassembly direction advances.
            return Some(READ_CHUNK);
        }
        let dir = self
            .dirs
            .iter()
            .flatten()
            .find(|dir| dir.flow == *flow)
            .or_else(|| self.pending.iter().find(|dir| dir.flow == *flow))?;
        Some(match dir.phase {
            DirectionPhase::Preface => PREFACE_LEN.saturating_sub(dir.buffer.len()),
            DirectionPhase::Frames => {
                if dir.buffer.len() < wire::HEADER_LEN {
                    wire::HEADER_LEN - dir.buffer.len()
                } else {
                    let bytes = dir.buffer.bytes();
                    let length = wire::declared_length(bytes);
                    (wire::HEADER_LEN + length).saturating_sub(dir.buffer.len())
                }
            }
            DirectionPhase::Prelude => {
                let head_pending = match self.side_of(&dir.flow) {
                    Some(Side::Client) => self
                        .prelude
                        .as_ref()
                        .is_none_or(|prelude| prelude.client_body.is_none()),
                    Some(_) => self
                        .prelude
                        .as_ref()
                        .is_none_or(|prelude| prelude.server_body.is_none()),
                    None => true,
                };
                if head_pending {
                    (crate::protocol::application::http::MAX_HEADER_BYTES + 1)
                        .saturating_sub(dir.buffer.len())
                        .min(READ_CHUNK)
                } else {
                    READ_CHUNK
                }
            }
            DirectionPhase::Sniff => {
                if dir.buffer.len() < PREFACE_LEN {
                    PREFACE_LEN - dir.buffer.len()
                } else {
                    READ_CHUNK
                }
            }
        })
    }

    fn pump(&mut self, context: &mut Context<'_>) -> Result<(), Error> {
        loop {
            context.check_deadline()?;
            match self.phase {
                Phase::Dead => return self.drain(context),
                Phase::Sniff => {
                    self.elect(context)?;
                    if matches!(self.phase, Phase::Sniff) {
                        return Ok(());
                    }
                }
                Phase::Prelude | Phase::H2 => {
                    if let Some(side) = self.resume_side.take() {
                        self.pump_side(side, context)?;
                        continue;
                    }
                    let before = self.buffered_len();
                    self.pump_side(Side::Client, context)?;
                    if self.resume_side.is_some() {
                        continue;
                    }
                    self.pump_side(Side::Server, context)?;
                    if self.resume_side.is_some() {
                        continue;
                    }
                    if !matches!(self.phase, Phase::Dead) && self.buffered_len() == before {
                        return Ok(());
                    }
                }
            }
        }
    }

    fn pump_side(&mut self, side: Side, context: &mut Context<'_>) -> Result<(), Error> {
        loop {
            if matches!(self.phase, Phase::Dead) {
                return Ok(());
            }
            let Some(dir) = self.dirs[side].as_ref() else {
                return Ok(());
            };
            if dir.buffer.is_empty() || (dir.closed && dir.phase != DirectionPhase::Frames) {
                return Ok(());
            }
            let progressed = match dir.phase {
                DirectionPhase::Preface => self.preface_step(side, context)?,
                DirectionPhase::Prelude => self.prelude_step(side, context)?,
                DirectionPhase::Frames => self.frame_step(side, context)?,
                DirectionPhase::Sniff => false,
            };
            if !progressed || self.resume_side.is_some() {
                return Ok(());
            }
        }
    }
}

impl ConnectionState {
    pub(crate) fn decoder_sync(
        &mut self,
        side: Side,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let dir = self.dirs[side]
            .as_mut()
            .ok_or(Error::Invariant("direction not found"))?;
        if let Some(decoder) = dir.decoder.as_ref() {
            let now = decoder.buffered_bytes();
            let charged = dir.decoder_charge.bytes();
            if now > charged {
                context.charge(&mut dir.decoder_charge, now - charged)?;
            } else {
                context.release(&mut dir.decoder_charge, charged - now)?;
            }
        }
        Ok(())
    }
}
