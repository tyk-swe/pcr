// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Connection phase state machine, input buffering, and processing pumps.

pub(crate) mod control;
pub(crate) mod directions;
pub(crate) mod frames;
pub(crate) mod lifecycle;
pub(crate) mod prelude;
pub(crate) mod reporter;
pub(crate) mod startup;
pub(crate) mod streams;

pub(crate) use super::budget::Context;
pub(crate) use control::{ControlState, PendingCounts};
pub(crate) use directions::{
    Chain, ChainHead, DirectionPhase, ElectedDirection, ElectedDirections, SniffingDirections,
};
pub(crate) use reporter::{Evidence, Fault, Reporter, StepAbort, StepResult};

use super::Error;
use super::budget::{self, Charge};
use super::model::{Certainty, PeerSettings, Status};
use super::stream::{HeadKind, MessageBuilder, StreamTable};
use super::upgrade::Prelude;
use crate::analysis::ScopedFlowKey;
use crate::analysis::application::{self, Delivery};
use crate::analysis::http2::side::Side;
use crate::analysis::provenance::SourceSet;
use crate::protocol::application::http;
use crate::protocol::application::http2 as wire;
use startup::Election;
use std::collections::VecDeque;

pub(crate) const PREFACE_LEN: usize = wire::CLIENT_PREFACE.len();
const READ_CHUNK: usize = 4096;

pub(crate) struct Head {
    pub kind: HeadKind,
    pub meta: super::headers::Meta,
    pub flawed: bool,
}

pub(crate) struct Pos {
    pub side: Side,
    pub stream_id: u32,
}

#[derive(Default)]
pub(crate) struct UpgradeEvidence {
    pub response: Option<http::Head>,
    pub sources: Option<SourceSet>,
    pub charge: Charge,
    pub refused: bool,
}

#[derive(Default)]
pub(crate) struct DeferredMessages {
    pub promises: VecDeque<MessageBuilder>,
    pub awaiting_ack: VecDeque<(Side, MessageBuilder, Status)>,
    pub resume_side: Option<Side>,
    charge: Charge,
}

impl DeferredMessages {
    pub(crate) fn push_promise(
        &mut self,
        msg: MessageBuilder,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        context.charge(&mut self.charge, budget::PENDING_OVERHEAD)?;
        self.promises.push_back(msg);
        Ok(())
    }

    pub(crate) fn take_parent_promises(
        &mut self,
        parent_id: u32,
        context: &mut Context<'_>,
    ) -> Result<Vec<MessageBuilder>, Error> {
        let count = self.promises.len();
        let mut released = Vec::new();
        for _ in 0..count {
            context.check_deadline()?;
            if let Some(msg) = self.promises.pop_front() {
                if msg.promised_by == Some(parent_id) {
                    context.release(&mut self.charge, budget::PENDING_OVERHEAD)?;
                    released.push(msg);
                } else {
                    self.promises.push_back(msg);
                }
            }
        }
        Ok(released)
    }

    pub(crate) fn take_all_promises(
        &mut self,
        context: &mut Context<'_>,
    ) -> Result<VecDeque<MessageBuilder>, Error> {
        let promises = std::mem::take(&mut self.promises);
        context.release(&mut self.charge, promises.len() * budget::PENDING_OVERHEAD)?;
        Ok(promises)
    }

    pub(crate) fn push_awaiting_ack(
        &mut self,
        side: Side,
        msg: MessageBuilder,
        status: Status,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        context.charge(&mut self.charge, budget::PENDING_OVERHEAD)?;
        self.awaiting_ack.push_back((side, msg, status));
        Ok(())
    }

    pub(crate) fn take_all_awaiting_ack(
        &mut self,
        context: &mut Context<'_>,
    ) -> Result<VecDeque<(Side, MessageBuilder, Status)>, Error> {
        let messages = std::mem::take(&mut self.awaiting_ack);
        context.release(&mut self.charge, messages.len() * budget::PENDING_OVERHEAD)?;
        Ok(messages)
    }

    pub(crate) fn release_all(&mut self, context: &mut Context<'_>) -> Result<(), Error> {
        for msg in self
            .promises
            .iter_mut()
            .chain(self.awaiting_ack.iter_mut().map(|(_, msg, _)| msg))
        {
            context.release_all(&mut msg.charge)?;
        }
        self.promises.clear();
        self.awaiting_ack.clear();
        self.resume_side = None;
        context.release_all(&mut self.charge)
    }
}

pub(crate) struct SniffingState {
    pub directions: SniffingDirections,
}

pub(crate) struct ActiveState {
    pub directions: ElectedDirections,
    pub streams: StreamTable,
    pub control: ControlState,
    pub prelude: Option<Prelude>,
    pub upgrade: UpgradeEvidence,
    pub deferred: DeferredMessages,
    pub clean_start: bool,
    pub done: bool,
    pub finalizing: bool,
    pub settings_audited: bool,
}

pub(crate) struct DeadState {
    pub flow: ScopedFlowKey,
    pub known_flows: Vec<ScopedFlowKey>,
    pub client_settings: PeerSettings,
    pub server_settings: PeerSettings,
    pub client_window: i64,
    pub server_window: i64,
    pub streams_admitted: u64,
    pub pending: PendingCounts,
    pub upgrade: UpgradeEvidence,
    pub overhead: Charge,
    pub unobserved_settings: Vec<(ScopedFlowKey, Certainty)>,
}

pub(crate) enum Phase {
    Sniffing(SniffingState),
    Active(Box<ActiveState>),
    Dead(Box<DeadState>),
}

pub(crate) struct ConnectionState {
    pub reporter: Reporter,
    pub phase: Phase,
}

impl ActiveState {
    pub(crate) fn new(
        directions: ElectedDirections,
        prelude: Option<Prelude>,
        clean_start: bool,
    ) -> Self {
        Self {
            directions,
            streams: StreamTable::new(),
            control: ControlState::new(),
            prelude,
            upgrade: UpgradeEvidence::default(),
            deferred: DeferredMessages::default(),
            clean_start,
            done: false,
            finalizing: false,
            settings_audited: false,
        }
    }

    pub(crate) fn is_h2(&self) -> bool {
        self.prelude.is_none()
    }

    pub(crate) fn waiting_settings_ack(&self, side: Side) -> bool {
        let peer = side.peer();
        if self.finalizing
            || !self.control.settings[peer].pending.is_empty()
            || self.directions.get(peer).is_some_and(|dir| dir.closed)
        {
            return false;
        }
        self.directions
            .get(side)
            .is_some_and(ElectedDirection::has_buffered_settings_ack)
    }

    pub(crate) fn waiting_any_settings_ack(&self) -> bool {
        self.waiting_settings_ack(Side::Client) || self.waiting_settings_ack(Side::Server)
    }

    pub(crate) fn next_want(&self, flow: &ScopedFlowKey) -> Option<usize> {
        let side = self.directions.side_of(flow)?;
        if self.waiting_settings_ack(side) {
            // The already charged directional buffer bounds deferred ACKs and
            // following bytes while the opposite reassembly direction advances.
            return Some(READ_CHUNK);
        }
        let dir = self.directions.get(side)?;
        Some(match dir.phase {
            DirectionPhase::Preface => PREFACE_LEN.saturating_sub(dir.buffer.len()),
            DirectionPhase::Frames => {
                if dir.buffer.len() < wire::HEADER_LEN {
                    wire::HEADER_LEN - dir.buffer.len()
                } else {
                    let length = wire::declared_length(dir.buffer.bytes());
                    (wire::HEADER_LEN + length).saturating_sub(dir.buffer.len())
                }
            }
            DirectionPhase::Prelude => {
                let head_pending = self
                    .prelude
                    .as_ref()
                    .is_none_or(|prelude| prelude.sides[side].body.is_none());
                if head_pending {
                    (http::MAX_HEADER_BYTES + 1)
                        .saturating_sub(dir.buffer.len())
                        .min(READ_CHUNK)
                } else {
                    READ_CHUNK
                }
            }
        })
    }

    pub(crate) fn pump(
        &mut self,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        loop {
            context.check_deadline()?;
            if let Some(side) = self.deferred.resume_side.take() {
                self.pump_side(side, reporter, context)?;
                continue;
            }
            let before = self.directions.buffered_len();
            self.pump_side(Side::Client, reporter, context)?;
            if self.deferred.resume_side.is_some() {
                continue;
            }
            self.pump_side(Side::Server, reporter, context)?;
            if self.deferred.resume_side.is_some() {
                continue;
            }
            if self.directions.buffered_len() == before {
                return Ok(());
            }
        }
    }

    fn pump_side(
        &mut self,
        side: Side,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        loop {
            let Some(dir) = self.directions.get(side) else {
                return Ok(());
            };
            if dir.buffer.is_empty() || (dir.closed && dir.phase != DirectionPhase::Frames) {
                return Ok(());
            }
            let progressed = match dir.phase {
                DirectionPhase::Preface => self.preface_step(side, reporter, context)?,
                DirectionPhase::Prelude => self.prelude_step(side, reporter, context)?,
                DirectionPhase::Frames => self.frame_step(side, reporter, context)?,
            };
            if !progressed || self.deferred.resume_side.is_some() {
                return Ok(());
            }
        }
    }
}

impl ConnectionState {
    pub(crate) fn new(stream: u64, generation: u64, flow: ScopedFlowKey) -> Self {
        Self {
            reporter: Reporter::new(stream, generation, flow),
            phase: Phase::Sniffing(SniffingState {
                directions: SniffingDirections::new(),
            }),
        }
    }

    pub(crate) fn set_frame_number(&mut self, number: u64) {
        self.reporter.number = number;
    }

    pub(crate) fn is_inactive(&self) -> bool {
        match &self.phase {
            Phase::Dead(_) => true,
            Phase::Active(active) => active.done,
            Phase::Sniffing(_) => false,
        }
    }

    pub(crate) fn has_flow(&self, flow: &ScopedFlowKey) -> bool {
        match &self.phase {
            Phase::Sniffing(sniff) => sniff.directions.has_flow(flow),
            Phase::Active(active) => active.directions.has_flow(flow),
            Phase::Dead(dead) => dead.known_flows.iter().any(|known| known == flow),
        }
    }

    pub(crate) fn primary_flow(&self) -> ScopedFlowKey {
        match &self.phase {
            Phase::Sniffing(sniff) => sniff.directions.primary_flow(&self.reporter.first_flow),
            Phase::Active(active) => active.directions.primary_flow(),
            Phase::Dead(dead) => dead.flow.clone(),
        }
    }

    pub(crate) fn data(
        &mut self,
        delivery: &Delivery,
        number: u64,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        self.reporter.number = number;
        if matches!(self.phase, Phase::Dead(_)) {
            return Ok(());
        }
        self.ensure_delivery_direction(&delivery.flow, !delivery.bytes.is_empty(), context)?;
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
                if matches!(self.phase, Phase::Dead(_)) {
                    return Ok(());
                }
                if self.buffered_len() == before {
                    return Err(Error::Application(application::Error::Limit {
                        field: "stalled_input",
                        limit: delivery.bytes.len(),
                    }));
                }
                continue;
            }
            let chunk = delivery.bytes.slice(cursor..cursor + want);
            self.push_bytes(&delivery.flow, chunk, delivery.sources.clone(), context)?;
            cursor += want;
            self.pump(context)?;
            if matches!(self.phase, Phase::Dead(_)) {
                return Ok(());
            }
        }
        Ok(())
    }

    fn ensure_delivery_direction(
        &mut self,
        flow: &ScopedFlowKey,
        has_bytes: bool,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        match &mut self.phase {
            Phase::Sniffing(sniff) => {
                sniff
                    .directions
                    .ensure_candidate(flow.clone(), false, context)?;
                if has_bytes && let Some(dir) = sniff.directions.find_mut(flow) {
                    dir.received = true;
                }
                Ok(())
            }
            Phase::Active(active) => {
                let phase = if active.is_h2() {
                    DirectionPhase::Frames
                } else {
                    DirectionPhase::Prelude
                };
                active.directions.ensure_server(
                    flow.clone(),
                    phase,
                    false,
                    &active.control.settings[Side::Client],
                    context,
                )
            }
            Phase::Dead(_) => Ok(()),
        }
    }

    fn next_want(&self, flow: &ScopedFlowKey) -> Option<usize> {
        match &self.phase {
            Phase::Sniffing(sniff) => {
                let dir = sniff.directions.find(flow)?;
                Some(if dir.buffer.len() < PREFACE_LEN {
                    PREFACE_LEN - dir.buffer.len()
                } else {
                    READ_CHUNK
                })
            }
            Phase::Active(active) => active.next_want(flow),
            Phase::Dead(_) => None,
        }
    }

    fn buffered_len(&self) -> usize {
        match &self.phase {
            Phase::Sniffing(sniff) => sniff.directions.buffered_len(),
            Phase::Active(active) => active.directions.buffered_len(),
            Phase::Dead(_) => 0,
        }
    }

    fn push_bytes(
        &mut self,
        flow: &ScopedFlowKey,
        chunk: bytes::Bytes,
        sources: SourceSet,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        match &mut self.phase {
            Phase::Sniffing(sniff) => {
                if let Some(dir) = sniff.directions.find_mut(flow) {
                    dir.buffer.push(chunk, sources, context)?;
                }
                Ok(())
            }
            Phase::Active(active) => {
                if let Some(side) = active.directions.side_of(flow)
                    && let Some(dir) = active.directions.get_mut(side)
                {
                    dir.buffer.push(chunk, sources, context)?;
                }
                Ok(())
            }
            Phase::Dead(_) => Ok(()),
        }
    }

    pub(crate) fn pump(&mut self, context: &mut Context<'_>) -> Result<(), Error> {
        loop {
            context.check_deadline()?;
            if let Phase::Sniffing(sniff) = &mut self.phase {
                match sniff.classify_candidates() {
                    Election::Pending => return Ok(()),
                    Election::Unsupported => {
                        self.reporter.status = Status::Unsupported;
                        return self.fail_to_dead(Status::Unsupported, context);
                    }
                    Election::Elected { index, startup } => {
                        self.promote_sniffing(index, startup, context)?;
                        continue;
                    }
                }
            }
            let Phase::Active(active) = &mut self.phase else {
                return Ok(());
            };
            return match active.pump(&mut self.reporter, context) {
                Ok(()) => Ok(()),
                Err(StepAbort::ConnectionFailed(status)) => self.fail_to_dead(status, context),
                Err(StepAbort::Fatal(error)) => Err(error),
            };
        }
    }
}
