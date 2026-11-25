// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Stream lifecycle, stream table ownership, and in-progress message builders.

use super::Error;
use super::IssueCode;
use super::budget::{self, Charge, Context};
use super::headers::FieldRole;
use super::model::{Header, MessageKind, Status};
use crate::analysis::http2::side::{PerSide, Side};
use crate::analysis::provenance::SourceSet;
use bytes::Bytes;
use std::collections::BTreeMap;
use std::ops::Bound;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Reserved,
    Open,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeadKind {
    Request,
    Response,
}

impl HeadKind {
    pub(crate) const fn field_role(self) -> FieldRole {
        match self {
            Self::Request => FieldRole::Request,
            Self::Response => FieldRole::Response,
        }
    }
}

pub(crate) struct Decoded {
    pub headers: Vec<Header>,
    pub block: Bytes,
    pub sources: Option<SourceSet>,
    pub compression: Option<SourceSet>,
}

pub(crate) enum HeaderSection {
    Initial,
    Trailers,
}

pub(crate) fn header_charge(headers: &[Header]) -> usize {
    headers
        .iter()
        .map(|header| header.name.len() + header.value.len() + budget::HEADER_OVERHEAD)
        .sum()
}

pub(crate) struct MessageBuilder {
    pub index: u64,
    pub stream_id: u32,
    pub kind: MessageKind,
    pub request: Option<u64>,
    pub promised_by: Option<u32>,
    pub headers: Vec<Header>,
    pub trailers: Vec<Header>,
    pub header_blocks: Vec<Bytes>,
    pub upgrade_head: Option<crate::protocol::application::http::Head>,
    pub body_bytes: u64,
    pub sets: Vec<SourceSet>,
    pub compression: Vec<SourceSet>,
    pub failure: Option<Status>,
    pub saw_body: bool,
    pub trailers_seen: bool,
    pub content_length: Option<u64>,
    pub status_code: Option<u16>,
    pub charge: Charge,
}

impl MessageBuilder {
    pub(crate) fn new(index: u64, stream_id: u32, kind: MessageKind) -> Self {
        Self {
            index,
            stream_id,
            kind,
            request: None,
            promised_by: None,
            headers: Vec::new(),
            trailers: Vec::new(),
            header_blocks: Vec::new(),
            upgrade_head: None,
            body_bytes: 0,
            sets: Vec::new(),
            compression: Vec::new(),
            failure: None,
            saw_body: false,
            trailers_seen: false,
            content_length: None,
            status_code: None,
            charge: Charge::default(),
        }
    }

    pub(crate) fn retain_headers(
        &mut self,
        section: HeaderSection,
        decoded: Decoded,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        context.charge(
            &mut self.charge,
            header_charge(&decoded.headers) + decoded.block.len(),
        )?;
        match section {
            HeaderSection::Initial => self.headers = decoded.headers,
            HeaderSection::Trailers => self.trailers.extend(decoded.headers),
        }
        self.header_blocks.push(decoded.block);
        if let Some(sources) = decoded.sources {
            context.track(&mut self.charge, &sources)?;
            self.sets.push(sources);
        }
        if let Some(sources) = decoded.compression {
            context.track(&mut self.charge, &sources)?;
            self.compression.push(sources);
        }
        Ok(())
    }

    pub(crate) fn content_charge(&self) -> usize {
        header_charge(&self.headers)
            + header_charge(&self.trailers)
            + self.header_blocks.iter().map(Bytes::len).sum::<usize>()
            + self
                .upgrade_head
                .as_ref()
                .map_or(0, |head| head.wire().len())
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct EarlyResponse {
    pub final_seen: bool,
    pub forbids_trailers: bool,
    /// The final status cannot carry content, so later DATA is a violation.
    pub bodyless: bool,
    pub ended: bool,
}

pub(crate) struct StreamState {
    pub phase: Phase,
    pub initiator: Side,
    pub promised_by: Option<u32>,
    pub ended: PerSide<bool>,
    pub request: Option<u64>,
    pub msgs: PerSide<Option<MessageBuilder>>,
    pub send_window: PerSide<i64>,
    pub credit_exceeded: PerSide<bool>,
    pub window_granted: PerSide<i64>,
    pub early_response: Option<EarlyResponse>,
    pub method: Option<Bytes>,
    pub response_bodyless: bool,
    pub unprocessed: bool,
}

impl StreamState {
    pub(crate) fn open(initiator: Side, windows: PerSide<i64>) -> Self {
        Self {
            phase: Phase::Open,
            initiator,
            promised_by: None,
            ended: PerSide::default(),
            request: None,
            msgs: PerSide::new(None, None),
            send_window: windows,
            credit_exceeded: PerSide::new(false, false),
            window_granted: PerSide::new(0, 0),
            early_response: None,
            method: None,
            response_bodyless: false,
            unprocessed: false,
        }
    }

    pub(crate) fn reserved(promised_by: u32, windows: PerSide<i64>) -> Self {
        let mut stream = Self::open(Side::Server, windows);
        stream.phase = Phase::Reserved;
        stream.promised_by = Some(promised_by);
        stream.ended = PerSide::new(true, false);
        stream
    }
}

pub(crate) struct ClosedStream {
    pub ended: PerSide<bool>,
    pub reset_by: Option<Side>,
    pub request: Option<u64>,
}

pub(crate) struct StreamTable {
    open: BTreeMap<u32, StreamState>,
    closed: BTreeMap<u32, ClosedStream>,
    early_responses: BTreeMap<u32, EarlyResponse>,
    closed_credit: BTreeMap<u32, PerSide<Option<i64>>>,
    pending_openers: BTreeMap<u32, IssueCode>,
    admitted: u64,
    max_initiated: PerSide<u32>,
    active: PerSide<usize>,
    non_closed_open: usize,
    next_origin: u64,
    charge: Charge,
}

impl StreamTable {
    pub(crate) fn new() -> Self {
        Self {
            open: BTreeMap::new(),
            closed: BTreeMap::new(),
            early_responses: BTreeMap::new(),
            closed_credit: BTreeMap::new(),
            pending_openers: BTreeMap::new(),
            admitted: 0,
            max_initiated: PerSide::new(0, 0),
            active: PerSide::new(0, 0),
            non_closed_open: 0,
            next_origin: 1,
            charge: Charge::default(),
        }
    }

    pub(crate) fn admitted(&self) -> u64 {
        self.admitted
    }

    pub(crate) fn next_origin(&mut self) -> u64 {
        let origin = self.next_origin;
        self.next_origin += 1;
        origin
    }

    pub(crate) fn max_initiated(&self, side: Side) -> u32 {
        self.max_initiated[side]
    }

    pub(crate) fn set_max_initiated(&mut self, side: Side, stream_id: u32) {
        self.max_initiated[side] = stream_id;
    }

    pub(crate) fn active_count(&self, initiator: Side) -> usize {
        self.active[initiator]
    }

    pub(crate) fn non_closed_count(&self) -> usize {
        self.non_closed_open
    }

    pub(crate) fn open_len(&self) -> usize {
        self.open.len()
    }

    pub(crate) fn open_get(&self, stream_id: u32) -> Option<&StreamState> {
        self.open.get(&stream_id)
    }

    pub(crate) fn open_mut(&mut self, stream_id: u32) -> Option<&mut StreamState> {
        self.open.get_mut(&stream_id)
    }

    pub(crate) fn is_open(&self, stream_id: u32) -> bool {
        self.open.contains_key(&stream_id)
    }

    pub(crate) fn is_closed_record(&self, stream_id: u32) -> bool {
        self.closed.contains_key(&stream_id)
    }

    pub(crate) fn is_closed_or_implicit(&self, stream_id: u32) -> bool {
        let initiator = Side::initiator_of(stream_id);
        self.closed.contains_key(&stream_id) || stream_id <= self.max_initiated[initiator]
    }

    pub(crate) fn is_peer_reset_in_flight(&self, side: Side, stream_id: u32) -> bool {
        self.closed
            .get(&stream_id)
            .is_some_and(|closed| closed.reset_by == Some(side.peer()) && !closed.ended[side])
    }

    pub(crate) fn early_response_for(&self, stream_id: u32) -> Option<EarlyResponse> {
        self.open
            .get(&stream_id)
            .and_then(|stream| stream.early_response)
            .or_else(|| self.early_responses.get(&stream_id).copied())
    }

    pub(crate) fn early_response(&self, stream_id: u32) -> Option<&EarlyResponse> {
        self.early_responses.get(&stream_id)
    }

    pub(crate) fn early_response_mut(&mut self, stream_id: u32) -> Option<&mut EarlyResponse> {
        self.early_responses.get_mut(&stream_id)
    }

    pub(crate) fn request_index(&self, stream_id: u32) -> Option<u64> {
        self.open
            .get(&stream_id)
            .and_then(|stream| stream.request)
            .or_else(|| {
                self.closed
                    .get(&stream_id)
                    .and_then(|stream| stream.request)
            })
    }

    pub(crate) fn open_iter(&self) -> impl Iterator<Item = (u32, &StreamState)> {
        self.open.iter().map(|(&id, stream)| (id, stream))
    }

    pub(crate) fn open_iter_mut(&mut self) -> impl Iterator<Item = (u32, &mut StreamState)> {
        self.open.iter_mut().map(|(&id, stream)| (id, stream))
    }

    pub(crate) fn closed_range(
        &self,
        range: (Bound<u32>, Bound<u32>),
    ) -> impl Iterator<Item = u32> + '_ {
        self.closed.range(range).map(|(&id, _)| id)
    }

    pub(crate) fn next_open_after(&self, cursor: u32) -> Option<u32> {
        self.open
            .range((Bound::Excluded(cursor), Bound::Unbounded))
            .next()
            .map(|(&id, _)| id)
    }

    pub(crate) fn next_closed_credit_after(&self, cursor: u32) -> Option<u32> {
        self.closed_credit
            .range((Bound::Excluded(cursor), Bound::Unbounded))
            .next()
            .map(|(&id, _)| id)
    }

    pub(crate) fn has_open_messages(&self) -> bool {
        self.open
            .values()
            .any(|stream| stream.msgs.iter().any(Option::is_some))
    }

    pub(crate) fn has_unfinished_open_streams(&self) -> bool {
        self.open
            .values()
            .any(|stream| !stream.ended.all(|ended| *ended))
    }

    pub(crate) fn ensure_early_response(
        &mut self,
        stream_id: u32,
        context: &mut Context<'_>,
    ) -> Result<&mut EarlyResponse, Error> {
        if !self.early_responses.contains_key(&stream_id) {
            context.check_streams()?;
            self.admitted += 1;
            context.charge(&mut self.charge, budget::CLOSED_STREAM_OVERHEAD)?;
            self.early_responses
                .insert(stream_id, EarlyResponse::default());
        }
        Ok(self.early_responses.entry(stream_id).or_default())
    }

    pub(crate) fn take_early_response(
        &mut self,
        stream_id: u32,
        context: &mut Context<'_>,
    ) -> Result<Option<EarlyResponse>, Error> {
        let early = self.early_responses.remove(&stream_id);
        if early.is_some() {
            context.release(&mut self.charge, budget::CLOSED_STREAM_OVERHEAD)?;
        }
        Ok(early)
    }

    pub(crate) fn admit_open(
        &mut self,
        stream_id: u32,
        state: StreamState,
        already_admitted: bool,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if !already_admitted {
            context.check_streams()?;
            self.admitted += 1;
        }
        context.charge(&mut self.charge, budget::STREAM_OVERHEAD)?;
        let initiator = state.initiator;
        self.open.insert(stream_id, state);
        self.active[initiator] += 1;
        self.non_closed_open += 1;
        Ok(())
    }

    pub(crate) fn admit_reserved(
        &mut self,
        stream_id: u32,
        state: StreamState,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        context.check_streams()?;
        self.admitted += 1;
        context.charge(&mut self.charge, budget::STREAM_OVERHEAD)?;
        self.open.insert(stream_id, state);
        self.non_closed_open += 1;
        Ok(())
    }

    pub(crate) fn admit_closed(
        &mut self,
        stream_id: u32,
        closed: ClosedStream,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        context.check_streams()?;
        self.admitted += 1;
        context.charge(&mut self.charge, budget::CLOSED_STREAM_OVERHEAD)?;
        self.closed.insert(stream_id, closed);
        Ok(())
    }

    pub(crate) fn promote_reserved(&mut self, stream_id: u32) -> bool {
        let Some(stream) = self.open.get_mut(&stream_id) else {
            return false;
        };
        if stream.phase != Phase::Reserved {
            return false;
        }
        stream.phase = Phase::Open;
        self.active[Side::Server] += 1;
        true
    }

    pub(crate) fn mark_open_closed_phase(&mut self, stream_id: u32) {
        let Some(stream) = self.open.get_mut(&stream_id) else {
            return;
        };
        if stream.phase == Phase::Open {
            let owner = stream.initiator;
            self.active[owner] = self.active[owner].saturating_sub(1);
        }
        if stream.phase != Phase::Closed {
            self.non_closed_open = self.non_closed_open.saturating_sub(1);
            stream.phase = Phase::Closed;
        }
    }

    pub(crate) fn move_open_to_closed(
        &mut self,
        stream_id: u32,
        closed: ClosedStream,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        self.retain_closed_credit(stream_id, context)?;
        if let Some(stream) = self.open.remove(&stream_id) {
            if stream.phase == Phase::Open {
                self.active[stream.initiator] = self.active[stream.initiator].saturating_sub(1);
            }
            if stream.phase != Phase::Closed {
                self.non_closed_open = self.non_closed_open.saturating_sub(1);
            }
        }
        self.closed.insert(stream_id, closed);
        context.release(
            &mut self.charge,
            budget::STREAM_OVERHEAD - budget::CLOSED_STREAM_OVERHEAD,
        )
    }

    pub(crate) fn retain_pending_opener(
        &mut self,
        stream_id: u32,
        code: IssueCode,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if !self.pending_openers.contains_key(&stream_id) {
            context.charge(&mut self.charge, budget::CLOSED_STREAM_OVERHEAD)?;
            self.pending_openers.insert(stream_id, code);
        }
        Ok(())
    }

    pub(crate) fn resolve_pending_opener(
        &mut self,
        stream_id: u32,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if self.pending_openers.remove(&stream_id).is_some() {
            context.release(&mut self.charge, budget::CLOSED_STREAM_OVERHEAD)?;
        }
        Ok(())
    }

    pub(crate) fn first_pending_opener(
        &self,
        owner: Side,
        below: Option<u32>,
        context: &Context<'_>,
    ) -> Result<Option<(u32, IssueCode)>, Error> {
        for (&id, &code) in &self.pending_openers {
            context.check_deadline()?;
            if Side::initiator_of(id) == owner && below.is_none_or(|bound| id < bound) {
                return Ok(Some((id, code)));
            }
        }
        Ok(None)
    }

    pub(crate) fn retain_closed_credit(
        &mut self,
        stream_id: u32,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let Some(stream) = self.open.get(&stream_id) else {
            return Ok(());
        };
        let debt_at = |side| {
            (stream.credit_exceeded[side] && stream.send_window[side] < 0)
                .then_some(stream.send_window[side])
        };
        let debt = PerSide::new(debt_at(Side::Client), debt_at(Side::Server));
        if debt.iter().any(Option::is_some) && !self.closed_credit.contains_key(&stream_id) {
            context.charge(&mut self.charge, budget::CLOSED_CREDIT_OVERHEAD)?;
            self.closed_credit.insert(stream_id, debt);
        }
        Ok(())
    }

    pub(crate) fn closed_credit_debt(&self, stream_id: u32, side: Side) -> Option<i64> {
        self.closed_credit
            .get(&stream_id)
            .and_then(|debt| debt[side])
    }

    pub(crate) fn clear_closed_credit_side(
        &mut self,
        stream_id: u32,
        side: Side,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if let Some(debt) = self.closed_credit.get_mut(&stream_id) {
            debt[side] = None;
            if debt.iter().all(Option::is_none) {
                self.closed_credit.remove(&stream_id);
                context.release(&mut self.charge, budget::CLOSED_CREDIT_OVERHEAD)?;
            }
        }
        Ok(())
    }

    pub(crate) fn credit_closed_stream(
        &mut self,
        stream_id: u32,
        grant: Side,
        increment: u32,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let Some(debt) = self.closed_credit.get_mut(&stream_id) else {
            return Ok(());
        };
        if let Some(window) = debt[grant].as_mut() {
            *window = window.saturating_add(i64::from(increment));
            if *window >= 0 {
                debt[grant] = None;
            }
        }
        if debt.iter().all(Option::is_none) {
            self.closed_credit.remove(&stream_id);
            context.release(&mut self.charge, budget::CLOSED_CREDIT_OVERHEAD)?;
        }
        Ok(())
    }

    pub(crate) fn apply_settings_delta_to_closed_credit(
        &mut self,
        side: Side,
        window_delta: i64,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        for debt in self.closed_credit.values_mut() {
            context.check_deadline()?;
            if let Some(window) = debt[side].as_mut() {
                *window += window_delta;
                if *window >= 0 {
                    debt[side] = None;
                }
            }
        }
        let before = self.closed_credit.len();
        self.closed_credit
            .retain(|_, debt| debt.iter().any(Option::is_some));
        context.release(
            &mut self.charge,
            (before - self.closed_credit.len()) * budget::CLOSED_CREDIT_OVERHEAD,
        )
    }

    pub(crate) fn drain_open_messages(&mut self) -> Vec<(Side, MessageBuilder)> {
        let mut drained = Vec::new();
        for stream in self.open.values_mut() {
            for side in Side::BOTH {
                if let Some(msg) = stream.msgs[side].take() {
                    drained.push((side, msg));
                }
            }
            stream.phase = Phase::Closed;
        }
        self.active = PerSide::new(0, 0);
        self.non_closed_open = 0;
        drained
    }

    pub(crate) fn release_all(&mut self, context: &mut Context<'_>) -> Result<(), Error> {
        for stream in self.open.values_mut() {
            for msg in stream.msgs.iter_mut().flatten() {
                context.release_all(&mut msg.charge)?;
            }
        }
        self.open.clear();
        self.closed.clear();
        self.early_responses.clear();
        self.pending_openers.clear();
        self.closed_credit.clear();
        self.active = PerSide::new(0, 0);
        self.non_closed_open = 0;
        context.release_all(&mut self.charge)
    }
}
