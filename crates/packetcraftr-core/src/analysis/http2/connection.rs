// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) mod control;
pub(crate) mod frames;
pub(crate) mod lifecycle;
pub(crate) mod prelude;
pub(crate) mod resources;
pub(crate) mod startup;
pub(crate) mod streams;

pub(crate) use resources::Cx;

use super::Error;
use super::buffer::SourceBuffer;
use super::model::{Certainty, Issue, IssueScope, Startup, Status};
use super::settings::DirectionSettings;
use super::stream::{CLIENT, SERVER, StreamState};
use super::upgrade::Prelude;
use crate::analysis::application::{self, Delivery};
use crate::analysis::provenance::SourceSet;
use crate::analysis::reassembly::tcp::ScopedFlowKey;
use crate::protocol::application::http2::hpack;
use bytes::Bytes;
use std::collections::{BTreeMap, HashMap};

pub(crate) const PREFACE_LEN: usize = 24;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Sniff,
    Prelude,
    H2,
    Dead,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirPhase {
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
    pub charged: usize,
    pub charged_spans: usize,
}
#[derive(Clone, Copy)]
pub(crate) enum ChainHead {
    Headers { end_stream: bool, malformed: bool },
    PushPromise { promised: u32 },
}

pub(crate) struct Dir {
    pub flow: ScopedFlowKey,
    pub phase: DirPhase,
    pub buffer: SourceBuffer,
    pub decoder: Option<hpack::Decoder>,
    pub decoder_charge: usize,
    pub block_sources: HashMap<u64, SourceSet>,
    pub chain: Option<Chain>,
    pub closed: bool,
    pub saw_frame: bool,
    pub garbage: bool,
    pub charged: usize,
    pub charged_spans: usize,
}
impl Dir {
    pub(crate) fn new(flow: ScopedFlowKey) -> Self {
        Self {
            flow,
            phase: DirPhase::Sniff,
            buffer: SourceBuffer::new(),
            decoder: None,
            decoder_charge: 0,
            block_sources: HashMap::new(),
            chain: None,
            closed: false,
            saw_frame: false,
            garbage: false,
            charged: 0,
            charged_spans: 0,
        }
    }
}

pub(crate) struct Fault {
    pub flow: ScopedFlowKey,
    pub http2_stream_id: Option<u32>,
    pub scope: IssueScope,
    pub certainty: Certainty,
    pub status: Status,
    pub code: &'static str,
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
    pub role: super::stream::FieldRole,
    pub meta: super::stream::Meta,
    pub flawed: bool,
}

pub(crate) struct Pos {
    pub side: usize,
    pub stream_id: u32,
}

#[derive(Clone)]
pub(crate) struct Evidence {
    pub wire: Bytes,
    pub sources: Option<SourceSet>,
}

pub(crate) struct ClosedStream {
    pub reset_by: Option<usize>,
    pub request: Option<u64>,
}

pub(crate) struct Conn {
    pub stream: u64,
    pub generation: u64,
    pub first_flow: ScopedFlowKey,
    pub startup: Startup,
    pub status: Status,
    pub phase: Phase,
    pub pending: Vec<Dir>,
    pub dirs: [Option<Dir>; 2],
    pub prelude: Option<Prelude>,
    pub streams: BTreeMap<u32, StreamState>,
    pub closed: BTreeMap<u32, ClosedStream>,
    pub admitted_streams: u64,
    pub max_initiated: [u32; 2],
    pub active: [usize; 2],
    pub send_window: [i64; 2],
    pub settings: [DirectionSettings; 2],
    pub goaway: [Option<u32>; 2],
    pub next_origin: u64,
    pub frames: u64,
    pub issues: u64,
    pub emitted: bool,
    pub clean_start: bool,
    pub number: u64,
    pub live: usize,
    pub upgrade_response: Option<crate::protocol::application::http::Head>,
    pub upgrade_sources: Option<SourceSet>,
    pub upgrade_charge: usize,
    pub final_pending_settings: Option<u64>,
    pub pings: [BTreeMap<[u8; 8], u64>; 2],
    pub final_pending_pings: Option<u64>,
    pub refused: bool,
    pub done: bool,
}

impl Conn {
    pub(crate) fn new(stream: u64, generation: u64, flow: ScopedFlowKey) -> Self {
        Self {
            stream,
            generation,
            first_flow: flow,
            startup: Startup::Unknown,
            status: Status::Complete,
            phase: Phase::Sniff,
            pending: Vec::new(),
            dirs: [None, None],
            prelude: None,
            streams: BTreeMap::new(),
            closed: BTreeMap::new(),
            admitted_streams: 0,
            max_initiated: [0, 0],
            active: [0, 0],
            send_window: [65_535, 65_535],
            settings: [DirectionSettings::new(), DirectionSettings::new()],
            goaway: [None, None],
            next_origin: 1,
            frames: 0,
            issues: 0,
            emitted: false,
            clean_start: true,
            number: 0,
            live: 0,
            upgrade_response: None,
            upgrade_sources: None,
            upgrade_charge: 0,
            final_pending_settings: None,
            pings: [BTreeMap::new(), BTreeMap::new()],
            final_pending_pings: None,
            refused: false,
            done: false,
        }
    }

    pub(crate) fn flow(&self) -> ScopedFlowKey {
        self.dirs[CLIENT]
            .as_ref()
            .or(self.dirs[SERVER].as_ref())
            .or_else(|| self.pending.first())
            .map(|dir| dir.flow.clone())
            .unwrap_or_else(|| self.first_flow.clone())
    }

    fn issue_frame_number(&self, sources: &Option<SourceSet>) -> Option<u64> {
        sources
            .as_ref()
            .and_then(|set| set.frames().last().map(|frame| frame.number))
    }

    pub(crate) fn dir_flow(&self, side: usize) -> ScopedFlowKey {
        self.dirs[side]
            .as_ref()
            .map(|dir| dir.flow.clone())
            .unwrap_or_else(|| self.flow())
    }

    pub(crate) fn dir_mut(&mut self, flow: &ScopedFlowKey) -> Option<&mut Dir> {
        self.dirs
            .iter_mut()
            .flatten()
            .find(|dir| dir.flow == *flow)
            .or_else(|| self.pending.iter_mut().find(|dir| dir.flow == *flow))
    }

    pub(crate) fn side_of(&self, flow: &ScopedFlowKey) -> Option<usize> {
        self.dirs
            .iter()
            .position(|dir| dir.as_ref().is_some_and(|dir| dir.flow == *flow))
    }

    pub(crate) fn has_flow(&self, flow: &ScopedFlowKey) -> bool {
        self.side_of(flow).is_some() || self.pending.iter().any(|dir| dir.flow == *flow)
    }

    pub(crate) fn issue(&mut self, cx: &mut Cx<'_>, fault: Fault) -> Result<(), Error> {
        let charge = fault.wire.len()
            + fault.detail.len()
            + resources::ISSUE_OVERHEAD
            + resources::EVENT_OVERHEAD;
        cx.charge_retained(charge)?;
        if let Some(sources) = &fault.sources {
            cx.charge_retained(
                resources::SET_OVERHEAD + sources.frames().len() * resources::SPAN_OVERHEAD,
            )?;
        }
        self.issues += 1;
        let number = self
            .issue_frame_number(&fault.sources)
            .unwrap_or(self.number);
        cx.issue(Issue {
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

    pub(crate) fn charge_conn(&mut self, cx: &mut Cx<'_>, bytes: usize) -> Result<(), Error> {
        cx.charge_live(bytes)?;
        self.live = self.live.checked_add(bytes).expect("conn charge");
        Ok(())
    }

    pub(crate) fn release_conn(&mut self, cx: &mut Cx<'_>, bytes: usize) {
        cx.release_live(bytes);
        self.live = self.live.checked_sub(bytes).expect("conn release");
    }

    pub(crate) fn charge_dir(dir: &mut Dir, cx: &mut Cx<'_>, bytes: usize) -> Result<(), Error> {
        cx.charge_live(bytes)?;
        dir.charged = dir.charged.checked_add(bytes).expect("dir charge");
        Ok(())
    }

    pub(crate) fn release_dir(dir: &mut Dir, cx: &mut Cx<'_>, bytes: usize) {
        cx.release_live(bytes);
        dir.charged = dir.charged.checked_sub(bytes).expect("dir release");
    }

    pub(crate) fn track_sources(
        dir: &mut Dir,
        cx: &mut Cx<'_>,
        set: &SourceSet,
    ) -> Result<(), Error> {
        cx.charge_sources(set)?;
        dir.charged_spans += set.frames().len();
        dir.charged += resources::SET_OVERHEAD + set.frames().len() * resources::SPAN_OVERHEAD;
        Ok(())
    }

    pub(crate) fn release_dropped(dir: &mut Dir, dropped: Vec<SourceSet>, cx: &mut Cx<'_>) {
        for set in dropped {
            let frames = set.frames().len();
            cx.release_sources(&set);
            dir.charged_spans -= frames;
            dir.charged -= resources::SET_OVERHEAD + frames * resources::SPAN_OVERHEAD;
        }
    }

    pub(crate) fn decoder_sync(&mut self, dir_index: usize, cx: &mut Cx<'_>) -> Result<(), Error> {
        let dir = self.dirs[dir_index].as_mut().ok_or(Error::Application(
            application::Error::Sources {
                number: self.number,
            },
        ))?;
        if let Some(decoder) = dir.decoder.as_ref() {
            let now = decoder.buffered_bytes();
            if now > dir.decoder_charge {
                Self::charge_dir(dir, cx, now - dir.decoder_charge)?;
            } else if now < dir.decoder_charge {
                Self::release_dir(dir, cx, dir.decoder_charge - now);
            }
            dir.decoder_charge = now;
        }
        Ok(())
    }

    pub(crate) fn data(
        &mut self,
        delivery: &Delivery,
        number: u64,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        self.number = number;
        if matches!(self.phase, Phase::Dead) {
            return Ok(());
        }
        if self.dir_mut(&delivery.flow).is_none() {
            let elected = self.dirs[CLIENT].is_some();
            if elected && self.dirs[SERVER].is_none() {
                let mut dir = Dir::new(delivery.flow.clone());
                let mut decoder = hpack::Decoder::new(cx.limits.hpack())?;
                decoder.permit_table_size(self.settings[CLIENT].advertised.header_table_size);
                for pending in &self.settings[CLIENT].pending {
                    decoder.permit_table_size(pending.final_values.header_table_size);
                }
                dir.decoder = Some(decoder);
                dir.phase = match self.phase {
                    Phase::H2 => DirPhase::Frames,
                    Phase::Prelude => DirPhase::Prelude,
                    _ => DirPhase::Sniff,
                };
                self.charge_conn(cx, resources::DIR_OVERHEAD)?;
                self.dirs[SERVER] = Some(dir);
            } else if !elected && self.pending.len() < 2 {
                self.charge_conn(cx, resources::DIR_OVERHEAD)?;
                self.pending.push(Dir::new(delivery.flow.clone()));
            }
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
                self.pump(cx)?;
                if self.buffered_len() == before {
                    return Err(Error::Application(application::Error::Limit {
                        field: "stalled_input",
                        limit: delivery.bytes.len(),
                    }));
                }
                if matches!(self.phase, Phase::Dead) {
                    return self.drain(cx);
                }
                continue;
            }
            let chunk = delivery.bytes.slice(cursor..cursor + want);
            let dir = self.dir_mut(&delivery.flow).expect("dir");
            Self::charge_dir(dir, cx, chunk.len())?;
            Self::track_sources(dir, cx, &delivery.sources)?;
            dir.buffer.push(chunk, delivery.sources.clone());
            cursor += want;
            self.pump(cx)?;
            if matches!(self.phase, Phase::Dead) {
                return self.drain(cx);
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

    fn next_want(&self, flow: &ScopedFlowKey) -> Option<usize> {
        let dir = self
            .dirs
            .iter()
            .flatten()
            .find(|dir| dir.flow == *flow)
            .or_else(|| self.pending.iter().find(|dir| dir.flow == *flow))?;
        Some(match dir.phase {
            DirPhase::Preface => PREFACE_LEN.saturating_sub(dir.buffer.len()),
            DirPhase::Frames => {
                if dir.buffer.len() < 9 {
                    9 - dir.buffer.len()
                } else {
                    let bytes = dir.buffer.bytes();
                    let length =
                        usize::try_from(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
                            .expect("24-bit frame length");
                    (9 + length).saturating_sub(dir.buffer.len())
                }
            }
            DirPhase::Prelude => {
                let head_pending = match self.side_of(&dir.flow) {
                    Some(CLIENT) => self
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
                        .min(4096)
                } else {
                    4096
                }
            }
            DirPhase::Sniff => {
                if dir.buffer.len() < PREFACE_LEN {
                    PREFACE_LEN - dir.buffer.len()
                } else {
                    4096
                }
            }
        })
    }

    fn pump(&mut self, cx: &mut Cx<'_>) -> Result<(), Error> {
        loop {
            cx.check_deadline()?;
            match self.phase {
                Phase::Dead => return self.drain(cx),
                Phase::Sniff => {
                    self.elect(cx)?;
                    if matches!(self.phase, Phase::Sniff) {
                        return Ok(());
                    }
                }
                Phase::Prelude | Phase::H2 => {
                    self.pump_side(CLIENT, cx)?;
                    self.pump_side(SERVER, cx)?;
                    if !matches!(self.phase, Phase::Dead) {
                        return Ok(());
                    }
                }
            }
        }
    }

    pub(crate) fn drain(&mut self, cx: &mut Cx<'_>) -> Result<(), Error> {
        let mut bytes = self.live - self.upgrade_charge;
        let mut spans = 0usize;
        for dir in self
            .dirs
            .iter_mut()
            .flatten()
            .chain(self.pending.iter_mut())
        {
            let pending = dir.buffer.len();
            let dropped = dir.buffer.discard(pending);
            let _ = dropped;
            bytes += dir.charged;
            spans += dir.charged_spans;
            dir.charged = 0;
            dir.charged_spans = 0;
            dir.decoder = None;
            dir.decoder_charge = 0;
            dir.block_sources = HashMap::new();
            dir.chain = None;
        }
        for stream in self.streams.values_mut() {
            for msg in stream.msgs.iter_mut().flatten() {
                spans += msg.charged_spans;
            }
        }
        if let Some(prelude) = self.prelude.as_mut() {
            for slot in [
                prelude.live_request.as_mut(),
                prelude.live_response.as_mut(),
            ]
            .into_iter()
            .flatten()
            {
                spans += slot.charged_spans;
            }
            for offer in prelude.offers.values_mut() {
                if let Some(msg) = offer.msg.as_mut() {
                    spans += msg.charged_spans;
                }
            }
        }
        self.final_pending_settings.get_or_insert(
            self.settings
                .iter()
                .map(|direction| direction.pending.len() as u64)
                .sum(),
        );
        for direction in self.settings.iter_mut() {
            direction.pending.clear();
        }
        self.final_pending_pings.get_or_insert(
            self.pings
                .iter()
                .map(|pings| pings.values().sum::<u64>())
                .sum::<u64>(),
        );
        for pings in self.pings.iter_mut() {
            pings.clear();
        }
        self.live = self.upgrade_charge;
        self.streams.clear();
        self.closed.clear();
        self.prelude = None;
        cx.release_live(bytes);
        *cx.spans = cx.spans.checked_sub(spans).expect("span release");
        Ok(())
    }

    fn pump_side(&mut self, side: usize, cx: &mut Cx<'_>) -> Result<(), Error> {
        loop {
            if matches!(self.phase, Phase::Dead) {
                return Ok(());
            }
            let Some(dir) = self.dirs[side].as_ref() else {
                return Ok(());
            };
            if dir.closed || dir.buffer.is_empty() {
                return Ok(());
            }
            let progressed = match dir.phase {
                DirPhase::Preface => self.preface_step(side, cx)?,
                DirPhase::Prelude => self.prelude_step(side, cx)?,
                DirPhase::Frames => self.frame_step(side, cx)?,
                DirPhase::Sniff => false,
            };
            if !progressed {
                return Ok(());
            }
        }
    }
}
